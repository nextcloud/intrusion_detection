<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Sensitive;

use OC\Session\Memory;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Lockdown\LockdownEffect;
use OCA\IntrusionDetection\Lockdown\LockdownState;
use OCA\IntrusionDetection\Sensitive\RiskySessions;
use OCA\IntrusionDetection\Sensitive\SensitiveSession;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IGroupManager;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;
use Test\TestCase;

/**
 * When a session is risky (concept section 11.13), and how long a
 * confirmation counts.
 */
class SensitiveSessionTest extends TestCase {
	private int $now = 1_760_000_000;
	/** @var array<string, mixed> */
	private array $values = [];
	private bool $lockdown = false;
	private bool $marked = false;
	private bool $admin = false;
	private SessionState $state;

	protected function setUp(): void {
		parent::setUp();
		$this->values = [
			GlobalSettings::SENSITIVE_ADMINS_ALWAYS => true,
			GlobalSettings::SENSITIVE_ADMIN_MAX_AGE => 3600,
			GlobalSettings::SENSITIVE_CONFIRM_TTL => 600,
		];
		$this->state = new SessionState(new Memory(), $this->createMock(LoggerInterface::class));
	}

	public function testANormalSessionIsNotRisky(): void {
		$this->assertNull($this->sensitive()->riskReason($this->state, 'alice'));
	}

	public function testEverySessionIsRiskyDuringLockdown(): void {
		$this->lockdown = true;
		$this->assertSame(SensitiveSession::REASON_LOCKDOWN, $this->sensitive()->riskReason($this->state, 'alice'));
	}

	public function testALoginAllowedWithoutConfirmationMakesItRisky(): void {
		$this->state->set(SessionState::CONFIRMATION, ['uid' => 'alice', 'by' => 'none', 'policies' => ['risky_network'], 'at' => $this->now]);
		$this->assertSame(SensitiveSession::REASON_UNCONFIRMED_LOGIN, $this->sensitive()->riskReason($this->state, 'alice'));
		$this->assertNull($this->sensitive()->riskReason($this->state, 'bob'), 'Only for the account it is about');

		$this->state->set(SessionState::CONFIRMATION, ['uid' => 'alice', 'by' => 'email_code', 'policies' => ['risky_network'], 'at' => $this->now]);
		$this->assertNull($this->sensitive()->riskReason($this->state, 'alice'), 'A confirmed login is not risky');
	}

	public function testADetectionInThisRequestMakesItRisky(): void {
		$this->sensitive()->markRisky($this->state, 'alice', 'account_takeover', 42);
		$this->assertSame(SensitiveSession::REASON_DETECTION, $this->sensitive()->riskReason($this->state, 'alice'));
		$this->assertSame(['uid' => 'alice', 'check' => 'account_takeover', 'detection' => 42, 'at' => $this->now], $this->state->get(SessionState::RISKY));
	}

	public function testADetectionInAnotherRequestMakesItRisky(): void {
		$this->marked = true;
		$this->assertSame(SensitiveSession::REASON_DETECTION, $this->sensitive()->riskReason($this->state, 'alice'));
	}

	public function testAnAdministratorWithoutARecentStrongConfirmationIsRisky(): void {
		$this->admin = true;
		$this->assertSame(SensitiveSession::REASON_ADMIN, $this->sensitive()->riskReason($this->state, 'admin'), 'Never confirmed');

		$this->sensitive()->strongConfirmation($this->state, 'admin');
		$this->assertNull($this->sensitive()->riskReason($this->state, 'admin'), 'Second factor just now');

		$this->now += 3601;
		$this->assertSame(SensitiveSession::REASON_ADMIN, $this->sensitive()->riskReason($this->state, 'admin'), 'An hour later');

		$this->sensitive()->confirmed($this->state, 'admin', 'email_code');
		$this->now += 3599;
		$this->assertNull($this->sensitive()->riskReason($this->state, 'admin'), 'A confirmed action counts as strong for the max age');
	}

	public function testAStrongLoginConfirmationCountsForAdministrators(): void {
		$this->admin = true;
		$this->state->set(SessionState::CONFIRMATION, ['uid' => 'admin', 'by' => 'second_factor', 'policies' => ['flagged_source'], 'at' => $this->now - 60]);
		$this->assertNull($this->sensitive()->riskReason($this->state, 'admin'));
		$this->state->set(SessionState::CONFIRMATION, ['uid' => 'admin', 'by' => 'known_device', 'policies' => ['flagged_source'], 'at' => $this->now - 60]);
		$this->assertSame(SensitiveSession::REASON_ADMIN, $this->sensitive()->riskReason($this->state, 'admin'), 'A remembered device is not a strong confirmation');
	}

	public function testTheAdministratorRuleCanBeSwitchedOff(): void {
		$this->admin = true;
		$this->values[GlobalSettings::SENSITIVE_ADMINS_ALWAYS] = false;
		$this->assertNull($this->sensitive()->riskReason($this->state, 'admin'));
		$this->values[GlobalSettings::SENSITIVE_ADMINS_ALWAYS] = true;
		$this->assertSame(SensitiveSession::REASON_ADMIN, $this->sensitive()->riskReason($this->state, 'admin'));
		$this->admin = false;
		$this->assertNull($this->sensitive()->riskReason($this->state, 'admin'), 'Only for administrators');
	}

	public function testAConfirmationLastsTheConfiguredTime(): void {
		$this->assertFalse($this->sensitive()->isConfirmed($this->state, 'alice'));
		$this->sensitive()->confirmed($this->state, 'alice', 'second_factor');
		$this->assertTrue($this->sensitive()->isConfirmed($this->state, 'alice'));
		$this->assertFalse($this->sensitive()->isConfirmed($this->state, 'bob'), 'Only for the account that confirmed');
		$this->now += 599;
		$this->assertTrue($this->sensitive()->isConfirmed($this->state, 'alice'));
		$this->now += 1;
		$this->assertFalse($this->sensitive()->isConfirmed($this->state, 'alice'));

		$this->values[GlobalSettings::SENSITIVE_CONFIRM_TTL] = 3600;
		$this->assertTrue($this->sensitive()->isConfirmed($this->state, 'alice'));
	}

	public function testASolvedSecondFactorIsNoConfirmationOfAnAction(): void {
		$this->sensitive()->strongConfirmation($this->state, 'alice');
		$this->assertFalse($this->sensitive()->isConfirmed($this->state, 'alice'));
		$this->assertSame($this->now, $this->sensitive()->lastStrong($this->state, 'alice'));
	}

	private function sensitive(): SensitiveSession {
		/** @var Settings&MockObject $settings */
		$settings = $this->createMock(Settings::class);
		$settings->method('getBool')->willReturnCallback(fn (string $name): bool => (bool)$this->values[$name]);
		$settings->method('getInt')->willReturnCallback(fn (string $name): int => (int)$this->values[$name]);
		$lockdown = $this->createMock(LockdownState::class);
		$lockdown->method('applies')->willReturnCallback(fn (LockdownEffect $effect): bool => $this->lockdown && $effect === LockdownEffect::Sensitive);
		$marks = $this->createMock(RiskySessions::class);
		$marks->method('isMarked')->willReturnCallback(fn (): bool => $this->marked);
		$groups = $this->createMock(IGroupManager::class);
		$groups->method('isAdmin')->willReturnCallback(fn (): bool => $this->admin);
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturnCallback(fn (): int => $this->now);
		return new SensitiveSession($settings, $lockdown, $marks, $groups, $time);
	}
}
