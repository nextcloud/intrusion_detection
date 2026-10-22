<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\Checks\StepUpFailed\StepUpFailed;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Confirm\AbandonedLogins;
use OCA\IntrusionDetection\Confirm\Db\StepUpSessionMapper;
use OCA\IntrusionDetection\Confirm\StepUpService;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\LoginHistory\Db\LoginHistoryMapper;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\Migration\Version1000Date20261021220000;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Notification\UserAlerts;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IUser;
use OCP\Migration\IOutput;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;

/**
 * Logins left waiting for their confirmation are ended by the background
 * job, as the step-up rule would end them on their next request.
 */
#[Group('DB')]
class AbandonedLoginsTest extends StepUpTestCase {
	private IUser $alice;

	protected function setUp(): void {
		parent::setUp();
		$this->alice = $this->user('ids-abandoned', 'alice@example.com');
		Server::get(FlaggedSources::class)->flagSource(SourceKey::fromIp($this->remoteAddress), FlaggedSources::REASON_ATTACK);
	}

	public function testALoginLeftWaitingIsEndedAtItsDeadlineAndTheUserIsTold(): void {
		$token = $this->startSession($this->alice);
		$this->login($this->alice);
		$this->assertTrue($this->stepUp()?->isPending());
		$historyId = Server::get(LoginHistoryMapper::class)->insert($this->alice->getUID(), time(), SourceKey::fromIp($this->remoteAddress), null, LoginHistory::METHOD_PASSWORD, false, 'none', LoginHistory::STEP_UP_PENDING, $token['id']);

		$this->assertSame(0, $this->abandoned()->purge(time()), 'Still within its deadline');
		$this->moveDeadline(time() - 1);
		$this->assertSame(1, $this->abandoned()->purge(time()));

		$detection = $this->detectionsOf(StepUpFailed::ID)[0];
		$this->assertSame(StepUpFailed::RULE_TIMEOUT, $detection->getExplanationData()['facts']['rule']);
		$this->assertSame([], Server::get(BanMapper::class)->findActiveForKeys([SourceKey::fromIp($this->remoteAddress)->ipKey], time()), 'A timeout never blocks');
		$this->assertFalse($this->tokenExists($token['id']), 'Its session is ended');
		$this->assertCount(1, $this->notificationsFor($this->alice->getUID(), UserAlerts::SUBJECT), 'The user is told');
		$row = Server::get(LoginHistoryMapper::class)->forUser($this->alice->getUID(), 0)[0];
		$this->assertSame([$historyId, LoginHistory::STEP_UP_FAILED, 'none'], [$row->id, $row->stepUp, $row->confirmedBy]);

		$this->assertSame(1, $this->unconfirmedRows(), 'Kept, so that the session cannot come back');
		$this->assertSame(0, $this->abandoned()->purge(time()), 'Once');
	}

	public function testAnApprovalThatExtendsTheWaitMovesTheDeadline(): void {
		$this->startSession($this->alice);
		$this->login($this->alice);
		$stepUp = $this->stepUp();
		$this->assertNotNull($stepUp);
		$this->moveDeadline(time() - 1);
		$stepUp->deadline = time() + 1800;
		$this->service()->save($stepUp);
		$this->assertSame(0, $this->abandoned()->purge(time()), 'Still waiting for an administrator');
	}

	public function testRefusedLoginsAndConfirmedOnesAreNotTouched(): void {
		$bob = $this->user('ids-abandoned-bob', null);
		$this->startSession($bob);
		$this->login($bob);
		$this->assertSame(1, $this->unconfirmedRows(), 'Refused: remembered without a deadline');
		$this->assertSame(0, $this->abandoned()->purge(time()));

		$this->session->clear();
		$this->startSession($this->alice);
		$this->login($this->alice);
		$this->verifyController()->confirm((string)$this->lastCode($this->alice->getUID()));
		$this->assertNull($this->stepUp());
		$this->moveDeadline(time() - 1);
		$this->assertSame(0, $this->abandoned()->purge(time()), 'A confirmed login is forgotten');
	}

	public function testWhileProtectionIsOffALoginPastItsDeadlineIsDroppedSilently(): void {
		$token = $this->startSession($this->alice);
		$this->login($this->alice);
		$historyId = Server::get(LoginHistoryMapper::class)->insert($this->alice->getUID(), time(), SourceKey::fromIp($this->remoteAddress), null, LoginHistory::METHOD_PASSWORD, false, 'none', LoginHistory::STEP_UP_PENDING, $token['id']);
		$this->settingsEditor()->setGlobal(GlobalSettings::ENABLED, false);
		$this->moveDeadline(time() - 1);

		$this->assertSame(1, $this->abandoned()->purge(time()));
		$this->assertSame([], $this->detectionsOf(StepUpFailed::ID), 'No detection');
		$this->assertSame([], $this->notificationsFor($this->alice->getUID(), UserAlerts::SUBJECT), 'Nobody is told');
		$row = Server::get(LoginHistoryMapper::class)->forUser($this->alice->getUID(), 0)[0];
		$this->assertSame([$historyId, LoginHistory::STEP_UP_FAILED], [$row->id, $row->stepUp]);
		$this->assertSame(1, $this->unconfirmedRows(), 'Kept, so that the session cannot come back');

		$this->settingsEditor()->setGlobal(GlobalSettings::ENABLED, true);
		$this->assertSame(0, $this->abandoned()->purge(time()), 'Turning protection back on tells nobody days later');
		$this->assertSame([], $this->detectionsOf(StepUpFailed::ID));
	}

	public function testPendingLoginsRememberedWithoutADeadlineGetOneOrEndQuietly(): void {
		$now = time();
		$mapper = Server::get(StepUpSessionMapper::class);
		$history = Server::get(LoginHistoryMapper::class);
		$source = SourceKey::fromIp($this->remoteAddress);
		// Waiting for a minute: it still may wait.
		$mapper->record(str_repeat('a', 64), $this->alice->getUID(), $now - 60, $now + 86400);
		$history->insert($this->alice->getUID(), $now - 60, $source, null, LoginHistory::METHOD_PASSWORD, false, 'none', LoginHistory::STEP_UP_PENDING, null);
		// Left waiting two hours ago.
		$carol = $this->user('ids-abandoned-old', 'carol@example.com');
		$mapper->record(str_repeat('c', 64), $carol->getUID(), $now - 7200, $now + 86400);
		$oldId = $history->insert($carol->getUID(), $now - 7200, $source, null, LoginHistory::METHOD_PASSWORD, false, 'none', LoginHistory::STEP_UP_PENDING, null);
		// Refused, and next to it a pending login of the same account in another session.
		$bob = $this->user('ids-abandoned-refused', null);
		$mapper->record(str_repeat('b', 64), $bob->getUID(), $now - 120, $now + 86400);
		$history->insert($bob->getUID(), $now - 120, $source, null, LoginHistory::METHOD_PASSWORD, false, 'none', LoginHistory::STEP_UP_REFUSED, null);
		$history->insert($bob->getUID(), $now - 117, $source, null, LoginHistory::METHOD_PASSWORD, false, 'none', LoginHistory::STEP_UP_PENDING, null);

		$migration = Server::get(Version1000Date20261021220000::class);
		$migration->postSchemaChange($this->createMock(IOutput::class), static fn () => null, []);

		$deadlines = array_column($this->deadlines(), 'deadline', 'uid');
		$this->assertSame($now - 60 + StepUpService::SESSION_TTL, $deadlines[$this->alice->getUID()] ?? null, 'When it started, plus the time a login may wait');
		$this->assertArrayHasKey($carol->getUID(), $deadlines);
		$this->assertNull($deadlines[$carol->getUID()], 'Past its time: no deadline the job would act on');
		$this->assertSame(LoginHistory::STEP_UP_FAILED, $history->forUser($carol->getUID(), 0)[0]->stepUp, 'Ended quietly');
		$this->assertSame($oldId, $history->forUser($carol->getUID(), 0)[0]->id);
		$this->assertArrayHasKey($bob->getUID(), $deadlines);
		$this->assertNull($deadlines[$bob->getUID()], 'A refused login keeps none, even next to a pending one');

		$this->assertSame(0, $this->abandoned()->purge(time()), 'Nothing is past its deadline yet');
		$this->assertSame([], $this->notificationsFor($carol->getUID(), UserAlerts::SUBJECT), 'Nobody is told about an old login');
		$this->assertSame([], $this->detectionsOf(StepUpFailed::ID));
	}

	/**
	 * @return list<array{uid: string, deadline: ?int}>
	 */
	private function deadlines(): array {
		$qb = $this->db->getQueryBuilder();
		$qb->select('uid', 'deadline')->from(StepUpSessionMapper::TABLE);
		$result = $qb->executeQuery();
		$rows = [];
		while ($row = $result->fetch()) {
			$rows[] = ['uid' => (string)$row['uid'], 'deadline' => $row['deadline'] === null ? null : (int)$row['deadline']];
		}
		$result->closeCursor();
		return $rows;
	}

	private function moveDeadline(int $deadline): void {
		$qb = $this->db->getQueryBuilder();
		$qb->update(StepUpSessionMapper::TABLE)
			->set('deadline', $qb->createNamedParameter($deadline, IQueryBuilder::PARAM_INT))
			->where($qb->expr()->isNotNull('deadline'))
			->executeStatement();
	}

	private function abandoned(): AbandonedLogins {
		return new AbandonedLogins(
			Server::get(StepUpSessionMapper::class),
			Server::get(LoginHistory::class),
			$this->engine(),
			$this->appSettings(),
			Server::get(AuditLogger::class),
			Server::get(LoggerInterface::class),
		);
	}
}
