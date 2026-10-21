<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Confirm;

use OCA\IntrusionDetection\Confirm\SessionConfirmation;
use OCA\IntrusionDetection\Confirm\UntrustedSecondFactors;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Config\IUserConfig;
use OCP\IUser;
use OCP\IUserSession;
use Test\TestCase;

/**
 * A second factor counts only once a session that proved more than the
 * password could have set it up, or a while after one that proved only
 * the password did.
 */
class UntrustedSecondFactorsTest extends TestCase {
	private int $now = 1_800_000_000;
	/** @var SessionConfirmation::* */
	private string $level = SessionConfirmation::PASSWORD;
	/** @var array<string, mixed> */
	private array $stored = [];

	public function testASecondFactorSetUpAfterOnlyThePasswordCountsAfterAWeek(): void {
		$untrusted = $this->untrusted();
		$untrusted->registered('alice', 'totp');
		$this->assertFalse($untrusted->isTrusted('alice', 'totp'));
		$this->assertSame(['totp' => $this->now], $untrusted->marks('alice'));

		$this->now += UntrustedSecondFactors::PASSWORD_DELAY - 1;
		$this->assertFalse($untrusted->isTrusted('alice', 'totp'), 'Not before the week is over');
		$this->now += 1;
		$this->assertTrue($untrusted->isTrusted('alice', 'totp'));
		$this->assertSame([], $untrusted->marks('alice'));
	}

	public function testAProvenSessionTrustsItAtOnce(): void {
		$untrusted = $this->untrusted();
		$untrusted->registered('alice', 'totp');
		$this->level = SessionConfirmation::PROVEN;
		$untrusted->registered('alice', 'totp');
		$this->assertTrue($untrusted->isTrusted('alice', 'totp'));
		$this->assertSame([], $this->stored, 'Nothing left to keep');
	}

	public function testAnUnconfirmedSessionNeverMakesItCountByItself(): void {
		$untrusted = $this->untrusted();
		$this->level = SessionConfirmation::UNCONFIRMED;
		$untrusted->registered('alice', 'totp');
		$this->now += 365 * 86400;
		$this->assertFalse($untrusted->isTrusted('alice', 'totp'));

		$this->level = SessionConfirmation::PASSWORD;
		$untrusted->registered('alice', 'totp');
		$this->assertFalse($untrusted->isTrusted('alice', 'totp'), 'Set up again after only the password: a week from now');
		$this->now += UntrustedSecondFactors::PASSWORD_DELAY;
		$this->assertTrue($untrusted->isTrusted('alice', 'totp'));
	}

	public function testOlderMarksAreReadAndRemovingTheProviderDropsItsMark(): void {
		$this->stored = ['totp' => $this->now - 100, 'u2f' => ['at' => $this->now, 'until' => $this->now + 10], 'old' => ['at' => 1, 'until' => 2], 'bad' => 'x'];
		$untrusted = $this->untrusted();
		$this->assertSame(['totp' => $this->now - 100, 'u2f' => $this->now], $untrusted->marks('alice'));
		$untrusted->unregistered('alice', 'totp');
		$this->assertSame(['u2f' => ['at' => $this->now, 'until' => $this->now + 10]], $this->stored, 'Ended and broken marks go with the next write');
	}

	public function testOnlyTheAccountsOwnSessionMarks(): void {
		$untrusted = $this->untrusted('admin');
		$untrusted->registered('alice', 'totp');
		$this->assertSame([], $this->stored);
	}

	private function untrusted(string $sessionUid = 'alice'): UntrustedSecondFactors {
		$config = $this->createMock(IUserConfig::class);
		$config->method('getValueArray')->willReturnCallback(fn (): array => $this->stored);
		$config->method('setValueArray')->willReturnCallback(function (string $uid, string $app, string $key, array $value): bool {
			$this->stored = $value;
			return true;
		});
		$config->method('deleteUserConfig')->willReturnCallback(function (): void {
			$this->stored = [];
		});
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn($sessionUid);
		$session = $this->createMock(IUserSession::class);
		$session->method('getUser')->willReturn($user);
		$confirmation = $this->createMock(SessionConfirmation::class);
		$confirmation->method('level')->willReturnCallback(fn (): string => $this->level);
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturnCallback(fn (): int => $this->now);
		return new UntrustedSecondFactors($config, $session, $confirmation, $time);
	}
}
