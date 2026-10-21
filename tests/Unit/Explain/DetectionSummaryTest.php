<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Explain;

use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\Checks\AccountUnderAttack;
use OCA\IntrusionDetection\Check\Checks\AdminChange;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffing;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Explain\DetectionHeadline;
use OCA\IntrusionDetection\Explain\DetectionSummary;
use OCA\IntrusionDetection\Response\ResponseOutcome;
use OCP\IL10N;
use OCP\L10N\IFactory;
use OCP\Server;
use Test\TestCase;

/**
 * The one sentence a detection opens with: what happened and the most
 * important thing that was done.
 */
class DetectionSummaryTest extends TestCase {
	private DetectionSummary $summary;
	private IL10N $l;

	protected function setUp(): void {
		parent::setUp();
		$this->summary = new DetectionSummary(new DetectionHeadline(Server::get(CheckRegistry::class)));
		$this->l = Server::get(IFactory::class)->get('intrusion_detection', 'en');
	}

	public function testTheCheckAndTheAddressThenTheBlock(): void {
		$detection = self::detection(CredentialStuffing::ID, '203.0.113.7', null, true, [
			['type' => 'notify_admin', 'enforced' => true],
			['type' => 'ban', 'enforced' => true],
		]);
		$this->assertSame('Credential stuffing from 203.0.113.7. The address was blocked.', $this->summary->summary($detection, $this->l));
	}

	public function testResponsesThatDidNotActAreSkipped(): void {
		$detection = self::detection(CredentialStuffing::ID, '203.0.113.7', null, true, [
			['type' => 'ban', 'enforced' => true, 'note' => ResponseOutcome::NOTE_HELD_BACK],
			['type' => 'flag_source', 'enforced' => true, 'note' => ResponseOutcome::NOTE_FAILED],
			['type' => 'notify_admin', 'enforced' => true],
		]);
		$this->assertSame('Credential stuffing from 203.0.113.7. The administrators were notified.', $this->summary->summary($detection, $this->l));
	}

	public function testAnAccountAndNothingToDo(): void {
		$detection = self::detection(AccountUnderAttack::ID, null, 'alice', true, []);
		$this->assertSame('One account attacked from many places: account alice. It was recorded.', $this->summary->summary($detection, $this->l));
	}

	public function testAnObservedDetectionSaysWhyNothingWasDone(): void {
		$learning = self::detection(CredentialStuffing::ID, '203.0.113.7', null, false, [['type' => 'ban', 'enforced' => false]], ModeState::REASON_LEARNING);
		$this->assertSame('Credential stuffing from 203.0.113.7. Only recorded, as learning mode was on.', $this->summary->summary($learning, $this->l));
		$observe = self::detection(CredentialStuffing::ID, '203.0.113.7', null, false, []);
		$this->assertSame('Only recorded, as the check observes.', $this->summary->outcome($observe, $this->l));
	}

	public function testAChecksOwnHeadlineIsUsed(): void {
		$detection = self::detection(AdminChange::ID, null, 'bob', true, [['type' => 'notify_admin', 'enforced' => true]], facts: ['kind' => AdminChange::KIND_ADMIN_GRANTED]);
		$this->assertSame('bob was made an administrator. The administrators were notified.', $this->summary->summary($detection, $this->l));
	}

	public function testADetectionOfARemovedCheckIsNamedByItsId(): void {
		$detection = self::detection('gone_check', '198.51.100.1', null, true, []);
		$this->assertSame('gone_check from 198.51.100.1. It was recorded.', $this->summary->summary($detection, $this->l));
	}

	public function testTheSentenceIsTranslated(): void {
		$l = $this->createMock(IL10N::class);
		$l->method('t')->willReturnCallback(static fn (string $text, array $parameters = []): string => '[' . vsprintf($text, $parameters) . ']');
		$detection = self::detection('gone_check', '198.51.100.1', null, true, [['type' => 'ban', 'enforced' => true]]);
		$this->assertSame('[[gone_check from 198.51.100.1]. [The address was blocked.]]', $this->summary->summary($detection, $l));
	}

	/**
	 * @param list<array{type: string, enforced: bool, note?: string}> $actions
	 * @param array<string, mixed> $facts
	 */
	private static function detection(string $checkId, ?string $ip, ?string $uid, bool $enforced, array $actions, ?string $reason = null, array $facts = []): Detection {
		$detection = new Detection();
		$detection->setCheckId($checkId);
		$detection->setIp($ip);
		$detection->setUid($uid);
		$detection->setEnforced($enforced);
		$detection->setActionList($actions);
		$detection->setExplanationData(['facts' => $facts, 'mode' => ['reason' => $reason]]);
		$detection->setHits(1);
		$detection->setCreatedAt(1_790_000_000);
		$detection->setLastSeenAt(1_790_000_000);
		return $detection;
	}
}
