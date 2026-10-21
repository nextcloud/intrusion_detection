<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Crypto;

use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IConfig;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;

class FingerprinterTest extends TestCase {
	private int $now = 1792411200; // 2026-10-19 12:00:00 UTC
	private ITimeFactory&MockObject $time;

	protected function setUp(): void {
		parent::setUp();
		$this->time = $this->createMock(ITimeFactory::class);
		$this->time->method('getTime')->willReturnCallback(fn (): int => $this->now);
	}

	private function fingerprinter(string $secret = 'instance-secret'): Fingerprinter {
		$config = $this->createMock(IConfig::class);
		$config->method('getSystemValueString')->with('secret')->willReturn($secret);
		return new Fingerprinter($config, $this->time);
	}

	public function testPasswordFingerprintIsSixteenBytesAndKeyed(): void {
		$a = $this->fingerprinter('one')->password('Summer2026!');
		$b = $this->fingerprinter('two')->password('Summer2026!');
		$this->assertSame(16, strlen($a));
		$this->assertNotSame($a, $b, 'A different instance secret must give a different fingerprint');
		$this->assertNotSame(hash('sha256', 'Summer2026!', true), $a);
	}

	public function testPasswordKeyRotatesDaily(): void {
		$f = $this->fingerprinter();
		$today = $f->password('Summer2026!');
		$this->now += 86400;
		$this->assertNotSame($today, $this->fingerprinter()->password('Summer2026!'));
	}

	public function testYesterdaysKeyIsTriedInTheFirstHourAfterMidnight(): void {
		$this->now = 1792368000 + 1800; // 00:30 UTC
		$f = $this->fingerprinter();
		$candidates = $f->passwordCandidates('Summer2026!');
		$this->assertCount(2, $candidates);

		$this->now = 1792368000 - 600; // 23:50 the day before
		$yesterday = $this->fingerprinter()->password('Summer2026!');
		$this->assertSame($yesterday, $candidates[1]);
	}

	public function testOnlyTodaysKeyLaterInTheDay(): void {
		$this->now = 1792368000 + 7200; // 02:00 UTC
		$this->assertCount(1, $this->fingerprinter()->passwordCandidates('Summer2026!'));
	}

	public function testAFlaggedPasswordIsRecognisedTomorrowToo(): void {
		$flagged = $this->fingerprinter()->passwordFlagFingerprints('Summer2026!');
		$this->assertSame($this->fingerprinter()->password('Summer2026!'), $flagged[0]);
		$this->now += 86400;
		$this->assertContains($this->fingerprinter()->password('Summer2026!'), $flagged);
	}

	public function testNamesAreNormalised(): void {
		$f = $this->fingerprinter();
		$this->assertSame($f->name('Alice'), $f->name('  alice '));
		$this->assertSame($f->name('ÄRGER'), $f->name('ärger'));
		$this->assertNotSame($f->name('alice'), $f->name('bob'));
	}

	public function testShareTokensKeepTheirCase(): void {
		$f = $this->fingerprinter();
		$this->assertSame(16, strlen($f->shareToken('AbCdEfGhJkLmNpQ')));
		$this->assertSame($f->shareToken('AbCdEfGhJkLmNpQ'), $f->shareToken(' AbCdEfGhJkLmNpQ '));
		$this->assertNotSame($f->shareToken('AbCdEfGhJkLmNpQ'), $f->shareToken('abcdefghjklmnpq'), 'Tokens that differ only in case are different guesses');
		$this->assertNotSame($f->name('abcdefghjklmnpq'), $f->shareToken('abcdefghjklmnpq'), 'Tokens and names use different keys');
		$this->assertNotSame($f->shareToken('AbCdEfGhJkLmNpQ'), $this->fingerprinter('other-secret')->shareToken('AbCdEfGhJkLmNpQ'));
	}

	public function testNameKeyDoesNotRotate(): void {
		$f = $this->fingerprinter();
		$before = $f->name('alice');
		$this->now += 5 * 86400;
		$this->assertSame($before, $this->fingerprinter()->name('alice'));
	}

	public function testPurposesUseDifferentKeys(): void {
		$f = $this->fingerprinter();
		$this->assertNotSame(substr($f->decoy('x'), 0, 16), $f->name('x'));
		$this->assertNotSame($f->device('x'), $f->decoy('x'));
	}

	public function testCredentialKeyIsUrlSafeAndShort(): void {
		$key = $this->fingerprinter()->credential('app-password-abc');
		$this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]{16}$/', $key);
	}

	public function testMissingSecretIsRefused(): void {
		$this->expectException(\RuntimeException::class);
		$this->fingerprinter('')->password('x');
	}
}
