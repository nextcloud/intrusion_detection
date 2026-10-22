<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\BackgroundJob\UserDetectionsCleanupJob;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffing\CredentialStuffing;
use OCA\IntrusionDetection\Check\Checks\SecondFactorFailed\SecondFactorFailed;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Db\AlertMapper;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Db\AttemptMapper;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Db\LockLinkMapper;
use OCA\IntrusionDetection\Db\LoginMapper;
use OCA\IntrusionDetection\Db\ProtectedAccountMapper;
use OCA\IntrusionDetection\Db\SecurityChangeMapper;
use OCA\IntrusionDetection\Db\TokenOriginMapper;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Detection\DetectionService;
use OCA\IntrusionDetection\Listener\UserDeletedListener;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Notification\UserAlerts;
use OCA\IntrusionDetection\Privacy\UserDataCleanup;
use OCP\BackgroundJob\IJobList;
use OCP\Server;
use OCP\User\Events\UserDeletedEvent;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;

/**
 * Concept section 12.3: a deleted account leaves nothing behind.
 */
#[Group('DB')]
class UserDeletedTest extends AccountTestCase {
	public function testEveryTraceOfTheAccountIsRemoved(): void {
		$user = $this->newUser('ids-gone');
		$uid = $user->getUID();
		$other = 'someone-else';
		$now = time();
		Server::get(TokenOriginMapper::class)->record(501, $uid, '203.0.113.1', null, $now);
		Server::get(TokenOriginMapper::class)->record(502, $other, '203.0.113.1', null, $now);
		Server::get(ProtectedAccountMapper::class)->protect($uid, 'under_attack', null, $now, $now + 3600);
		Server::get(ProtectedAccountMapper::class)->protect($other, 'under_attack', null, $now, $now + 3600);
		Server::get(AttemptMapper::class)->insert(AttemptKind::PasswordLogin, '203.0.113.1', '203.0.113.0/24', null, $uid, null, null, $now);
		Server::get(LoginMapper::class)->record('203.0.113.1', '203.0.113.0/24', $uid, intdiv($now, 3600));
		Server::get(LoginMapper::class)->record('203.0.113.1', '203.0.113.0/24', $other, intdiv($now, 3600));
		Server::get(AlertMapper::class)->hit(SecondFactorFailed::ID, UserAlerts::KEY_PREFIX . $uid, 1, null, $now);
		Server::get(AlertMapper::class)->hit(SecondFactorFailed::ID, UserAlerts::KEY_PREFIX . $other, 1, null, $now);
		Server::get(AlertMapper::class)->hit(SecondFactorFailed::ID, UserAlerts::FURTHER_KEY_PREFIX . $uid, 1, null, $now);

		$service = Server::get(DetectionService::class);
		$protect = new ModeState(Mode::Protect, Mode::Protect);
		[$own] = $service->record(new DetectionDraft(SecondFactorFailed::ID, SourceKey::fromIp('203.0.113.1'), $uid, ['sessionTokenId' => 9], merge: DetectionDraft::MERGE_SOURCE_USER), $protect);
		$service->setActions($own, [['type' => ResponseType::ForcePasswordChange->value, 'enforced' => true, 'ref' => ['uid' => $uid, 'state' => 'required']]]);
		[$attack] = $service->record(new DetectionDraft(CredentialStuffing::ID, SourceKey::fromIp('203.0.113.2'), null, ['targets' => [$other, $uid], 'failures' => 12]), $protect);
		[$unrelated] = $service->record(new DetectionDraft(CredentialStuffing::ID, SourceKey::fromIp('203.0.113.3'), null, ['targets' => [$other]]), $protect);

		$user->delete();
		// Run it directly too, in case the app's listeners are not registered in this test run; it is idempotent.
		(new UserDeletedListener(Server::get(UserDataCleanup::class), Server::get(LoggerInterface::class)))->handle(new UserDeletedEvent($user));
		$this->assertSame([$other, $uid], Server::get(DetectionMapper::class)->findById($attack->getId())->getExplanationData()['facts']['targets'], 'The detections are rewritten later, by a job');
		$this->runQueuedCleanup();

		$dump = '';
		foreach (IntegrationTestCase::TABLES as $table) {
			$result = $this->db->getQueryBuilder()->select('*')->from($table)->executeQuery();
			$dump .= json_encode($result->fetchAll(), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
			$result->closeCursor();
		}
		$this->assertStringNotContainsString($uid, $dump, 'The account appears in no table');
		$this->assertStringContainsString($other, $dump, 'Other accounts are untouched');

		$this->assertNotNull(Server::get(TokenOriginMapper::class)->find(502));
		$this->assertSame(1, count(Server::get(LoginMapper::class)->distinctUidsForIp('203.0.113.1', 0, 100)));
		$this->assertSame(1, Server::get(AttemptMapper::class)->stats('ip_key', ['203.0.113.1'], [], 0)->failures, 'The attempt still counts against its address');

		$mapper = Server::get(DetectionMapper::class);
		$own = $mapper->findById($own->getId());
		$this->assertNull($own->getUid());
		$this->assertNull($own->getMergeKey());
		$this->assertSame(9, $own->getExplanationData()['facts']['sessionTokenId'], 'The detection still explains what happened');
		$this->assertNull($own->getActionList()[0]['ref']['uid']);
		$this->assertSame([$other], $mapper->findById($attack->getId())->getExplanationData()['facts']['targets']);
		$this->assertSame(12, $mapper->findById($attack->getId())->getExplanationData()['facts']['failures']);
		$this->assertSame([$other], $mapper->findById($unrelated->getId())->getExplanationData()['facts']['targets']);
	}

	public function testTheDeletionCostsTheSameForAnAccountInManyDetectionsAndTheJobGoesInBatches(): void {
		$service = Server::get(DetectionService::class);
		$protect = new ModeState(Mode::Protect, Mode::Protect);
		$count = UserDataCleanup::BATCH + 5;
		for ($i = 0; $i < $count; $i++) {
			$service->record(new DetectionDraft(CredentialStuffing::ID, SourceKey::fromIp('203.0.113.9'), null, ['targets' => ['many-user', 'kept-user'], 'n' => $i]), $protect);
		}
		[$few] = $service->record(new DetectionDraft(CredentialStuffing::ID, SourceKey::fromIp('203.0.113.8'), null, ['targets' => ['few-user']]), $protect);

		$cleanup = Server::get(UserDataCleanup::class);
		$queries = $this->db->getInner()->getStats()['executed'];
		$cleanup->deleteUser('few-user');
		$few = $this->db->getInner()->getStats()['executed'] - $queries;
		$queries = $this->db->getInner()->getStats()['executed'];
		$cleanup->deleteUser('many-user');
		$this->assertSame($few, $this->db->getInner()->getStats()['executed'] - $queries, 'No query per detection in the deletion');

		$upTo = Server::get(DetectionMapper::class)->lastId();
		$this->assertSame(0, $cleanup->scrubDetections('many-user', $upTo, 0, 0), 'nothing done without a batch');
		$after = $cleanup->scrubDetections('many-user', $upTo, 0, 1);
		$this->assertNotNull($after, 'one batch, more to do');
		$this->assertNull($cleanup->scrubDetections('many-user', $upTo, $after, 1));
		$this->runQueuedCleanup();

		$dump = json_encode(array_map(static fn ($d) => $d->getExplanationData(), Server::get(DetectionMapper::class)->findList(new \OCA\IntrusionDetection\Db\DetectionFilter(limit: 1000))), JSON_THROW_ON_ERROR);
		$this->assertStringNotContainsString('many-user', $dump);
		$this->assertStringNotContainsString('few-user', $dump);
		$this->assertSame($count, substr_count($dump, 'kept-user'));
		$this->assertSame([], Server::get(\OCA\IntrusionDetection\Db\DetectionAccountMapper::class)->detectionIds('many-user', 0, 10));
	}

	public function testANewAccountWithTheNameOfADeletedOneKeepsItsDetections(): void {
		$service = Server::get(DetectionService::class);
		$protect = new ModeState(Mode::Protect, Mode::Protect);
		$service->record(new DetectionDraft(CredentialStuffing::ID, SourceKey::fromIp('203.0.113.9'), null, ['targets' => ['reused']]), $protect);
		Server::get(UserDataCleanup::class)->deleteUser('reused');
		[$later] = $service->record(new DetectionDraft(CredentialStuffing::ID, SourceKey::fromIp('203.0.113.7'), null, ['targets' => ['reused']]), $protect);
		$this->runQueuedCleanup();
		$this->assertSame(['reused'], Server::get(DetectionMapper::class)->findById($later->getId())->getExplanationData()['facts']['targets']);
	}

	private function runQueuedCleanup(): void {
		$jobs = Server::get(IJobList::class);
		for ($round = 0; $round < 10; $round++) {
			$ran = false;
			foreach ($jobs->getJobsIterator(UserDetectionsCleanupJob::class, null, 0) as $job) {
				$job->start($jobs);
				$ran = true;
			}
			if (!$ran) {
				return;
			}
		}
		$this->fail('The cleanup job keeps queueing itself');
	}

	public function testApprovalRequestsAndResetSuppressionsAboutTheAccountGoToo(): void {
		$now = time();
		foreach (['gone-user', 'kept-user'] as $uid) {
			$qb = $this->db->getQueryBuilder();
			$qb->insert('ids_approvals')->values([
				'kind' => $qb->createNamedParameter('admin_grant'),
				'subject_uid' => $qb->createNamedParameter($uid),
				'requested_by' => $qb->createNamedParameter('admin'),
				'group_id' => $qb->createNamedParameter('admin'),
				'status' => $qb->createNamedParameter('pending'),
				'created_at' => $qb->createNamedParameter($now, \OCP\DB\QueryBuilder\IQueryBuilder::PARAM_INT),
				'expires_at' => $qb->createNamedParameter($now + 3600, \OCP\DB\QueryBuilder\IQueryBuilder::PARAM_INT),
			])->executeStatement();
			$qb = $this->db->getQueryBuilder();
			$qb->insert('ids_reset_suppressions')->values([
				'uid' => $qb->createNamedParameter($uid),
				'created_at' => $qb->createNamedParameter($now, \OCP\DB\QueryBuilder\IQueryBuilder::PARAM_INT),
				'expires_at' => $qb->createNamedParameter($now + 3600, \OCP\DB\QueryBuilder\IQueryBuilder::PARAM_INT),
			])->executeStatement();
		}

		Server::get(UserDataCleanup::class)->deleteUser('gone-user');

		foreach (['ids_approvals' => 'subject_uid', 'ids_reset_suppressions' => 'uid'] as $table => $column) {
			$qb = $this->db->getQueryBuilder();
			$qb->select($column)->from($table);
			$result = $qb->executeQuery();
			$this->assertSame(['kept-user'], array_map('strval', $result->fetchFirstColumn()), $table);
			$result->closeCursor();
		}
	}

	public function testSecurityChangesAndLockLinksOfTheAccountGoToo(): void {
		$now = time();
		foreach (['gone-user', 'kept-user'] as $uid) {
			Server::get(SecurityChangeMapper::class)->insert(['uid' => $uid, 'type' => 'email_changed', 'via' => 'self', 'actor_uid' => $uid, 'old_value_hint' => 'o***@example.com', 'new_value_hint' => null, 'notify_to' => 'encrypted', 'ref_id' => null, 'detail' => null, 'session_token_id' => null, 'ip' => null, 'created_at' => $now]);
			Server::get(LockLinkMapper::class)->insert($uid, str_repeat('c', 64), 'o***@example.com', null, null, $now, $now + 3600);
		}

		Server::get(UserDataCleanup::class)->deleteUser('gone-user');

		foreach ([SecurityChangeMapper::TABLE, LockLinkMapper::TABLE] as $table) {
			$qb = $this->db->getQueryBuilder();
			$qb->select('uid')->from($table);
			$result = $qb->executeQuery();
			$this->assertSame(['kept-user'], array_map('strval', $result->fetchFirstColumn()), $table);
			$result->closeCursor();
		}
	}

	public function testWithoutRemovesTheAccountFromListsAndValues(): void {
		$this->assertSame(
			['targets' => ['bob'], 'uid' => null, 'nested' => ['by' => null, 'keep' => 'alice2'], 'count' => 3],
			UserDataCleanup::without(['targets' => ['alice', 'bob'], 'uid' => 'alice', 'nested' => ['by' => 'alice', 'keep' => 'alice2'], 'count' => 3], 'alice'),
		);
	}
}
