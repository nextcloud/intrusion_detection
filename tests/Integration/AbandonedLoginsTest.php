<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\Checks\StepUpFailed;
use OCA\IntrusionDetection\Confirm\AbandonedLogins;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Db\LoginHistoryMapper;
use OCA\IntrusionDetection\Db\StepUpSessionMapper;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Notification\UserAlerts;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IUser;
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

		$this->assertSame(0, $this->abandoned()->end(), 'Still within its deadline');
		$this->moveDeadline(time() - 1);
		$this->assertSame(1, $this->abandoned()->end());

		$detection = $this->detectionsOf(StepUpFailed::ID)[0];
		$this->assertSame(StepUpFailed::RULE_TIMEOUT, $detection->getExplanationData()['facts']['rule']);
		$this->assertSame([], Server::get(BanMapper::class)->findActiveForKeys([SourceKey::fromIp($this->remoteAddress)->ipKey], time()), 'A timeout never blocks');
		$this->assertFalse($this->tokenExists($token['id']), 'Its session is ended');
		$this->assertCount(1, $this->notificationsFor($this->alice->getUID(), UserAlerts::SUBJECT), 'The user is told');
		$row = Server::get(LoginHistoryMapper::class)->forUser($this->alice->getUID(), 0)[0];
		$this->assertSame([$historyId, LoginHistory::STEP_UP_FAILED, 'none'], [$row->id, $row->stepUp, $row->confirmedBy]);

		$this->assertSame(1, $this->unconfirmedRows(), 'Kept, so that the session cannot come back');
		$this->assertSame(0, $this->abandoned()->end(), 'Once');
	}

	public function testAnApprovalThatExtendsTheWaitMovesTheDeadline(): void {
		$this->startSession($this->alice);
		$this->login($this->alice);
		$stepUp = $this->stepUp();
		$this->assertNotNull($stepUp);
		$this->moveDeadline(time() - 1);
		$stepUp->deadline = time() + 1800;
		$this->service()->save($stepUp);
		$this->assertSame(0, $this->abandoned()->end(), 'Still waiting for an administrator');
	}

	public function testRefusedLoginsAndConfirmedOnesAreNotTouched(): void {
		$bob = $this->user('ids-abandoned-bob', null);
		$this->startSession($bob);
		$this->login($bob);
		$this->assertSame(1, $this->unconfirmedRows(), 'Refused: remembered without a deadline');
		$this->assertSame(0, $this->abandoned()->end());

		$this->session->clear();
		$this->startSession($this->alice);
		$this->login($this->alice);
		$this->verifyController()->confirm((string)$this->lastCode($this->alice->getUID()));
		$this->assertNull($this->stepUp());
		$this->moveDeadline(time() - 1);
		$this->assertSame(0, $this->abandoned()->end(), 'A confirmed login is forgotten');
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
			Server::get(LoginHistoryMapper::class),
			$this->engine(),
			Server::get(StepUpFailed::class),
			$this->settings,
			Server::get(ITimeFactory::class),
			Server::get(AuditLogger::class),
			Server::get(LoggerInterface::class),
		);
	}
}
