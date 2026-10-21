<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Check\Checks\CredentialStuffing;
use OCA\IntrusionDetection\Check\Checks\SecondFactorFailed;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Db\AlertMapper;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Db\AttemptMapper;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Db\LoginMapper;
use OCA\IntrusionDetection\Db\ProtectedAccountMapper;
use OCA\IntrusionDetection\Db\TokenOriginMapper;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Detection\DetectionService;
use OCA\IntrusionDetection\Listener\UserDeletedListener;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Notification\UserAlerts;
use OCA\IntrusionDetection\Privacy\UserDataCleanup;
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

		$service = Server::get(DetectionService::class);
		$protect = new ModeState(Mode::Protect, Mode::Protect);
		[$own] = $service->record(new DetectionDraft(SecondFactorFailed::ID, SourceKey::fromIp('203.0.113.1'), $uid, ['sessionTokenId' => 9], merge: DetectionDraft::MERGE_SOURCE_USER), $protect);
		$service->setActions($own, [['type' => ResponseType::ForcePasswordChange->value, 'enforced' => true, 'ref' => ['uid' => $uid, 'state' => 'required']]]);
		[$attack] = $service->record(new DetectionDraft(CredentialStuffing::ID, SourceKey::fromIp('203.0.113.2'), null, ['targets' => [$other, $uid], 'failures' => 12]), $protect);
		[$unrelated] = $service->record(new DetectionDraft(CredentialStuffing::ID, SourceKey::fromIp('203.0.113.3'), null, ['targets' => [$other]]), $protect);

		$user->delete();
		// Run it directly too, in case the app's listeners are not registered in this test run; it is idempotent.
		(new UserDeletedListener(Server::get(UserDataCleanup::class), Server::get(LoggerInterface::class)))->handle(new UserDeletedEvent($user));

		$dump = '';
		foreach (IntegrationTestCase::TABLES as $table) {
			$result = $this->db->getQueryBuilder()->select('*')->from($table)->executeQuery();
			$dump .= json_encode($result->fetchAll(), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
			$result->closeCursor();
		}
		$this->assertStringNotContainsString($uid, $dump, 'The account appears in no table');
		$this->assertStringContainsString($other, $dump, 'Other accounts are untouched');

		$this->assertNotNull(Server::get(TokenOriginMapper::class)->find(502));
		$this->assertSame(1, Server::get(LoginMapper::class)->distinctUsersForIp('203.0.113.1', 0));
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

	public function testWithoutRemovesTheAccountFromListsAndValues(): void {
		$this->assertSame(
			['targets' => ['bob'], 'uid' => null, 'nested' => ['by' => null, 'keep' => 'alice2'], 'count' => 3],
			UserDataCleanup::without(['targets' => ['alice', 'bob'], 'uid' => 'alice', 'nested' => ['by' => 'alice', 'keep' => 'alice2'], 'count' => 3], 'alice'),
		);
	}
}
