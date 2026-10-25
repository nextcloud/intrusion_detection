<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\LoginHistory;

use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\LoginHistory\LoginHistoryEntry;
use OCA\IntrusionDetection\LoginHistory\SignInHabits;
use Test\TestCase;

class SignInHabitsTest extends TestCase {
	private const FIREFOX_LINUX = 'Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0';
	private const CHROME_WINDOWS = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36';
	/** 2026-10-20 12:00 UTC */
	private const NOON = 1792497600;

	private int $id = 0;

	public function testTheUsualNetworkAndDeviceGetNoWarning(): void {
		$habits = $this->habits([
			$this->login(self::NOON - 86400, '198.51.100.0/24', self::FIREFOX_LINUX),
		]);

		$this->assertSame([SignInHabits::USUAL_NETWORK], $habits->labels(self::NOON, '198.51.100.0/24', self::FIREFOX_LINUX, false, true));
	}

	public function testANewNetworkAndDevice(): void {
		$habits = $this->habits([
			$this->login(self::NOON - 86400, '198.51.100.0/24', self::FIREFOX_LINUX),
		]);

		$this->assertSame([SignInHabits::NEW_NETWORK, SignInHabits::NEW_DEVICE], $habits->labels(self::NOON, '203.0.113.0/24', self::CHROME_WINDOWS, false, true));
		$this->assertSame([SignInHabits::NEW_NETWORK], $habits->labels(self::NOON, '203.0.113.0/24', self::CHROME_WINDOWS, true, true), 'A remembered device is not new');
		$this->assertSame([SignInHabits::NEW_NETWORK], $habits->labels(self::NOON, '203.0.113.0/24', 'curl/8.0', false, true), 'No device to compare');
	}

	public function testATrustedNetworkIsUsualWithoutAnyLoginFromThere(): void {
		$habits = $this->habits([
			$this->login(self::NOON - 86400, '198.51.100.0/24', self::FIREFOX_LINUX),
		], ['203.0.113.0/24']);

		$this->assertSame([SignInHabits::USUAL_NETWORK], $habits->labels(self::NOON, '203.0.113.0/24', self::FIREFOX_LINUX, false, true));
	}

	public function testOnlyLoginsThatWentThroughInTheWindowBeforeCount(): void {
		$habits = $this->habits([
			$this->login(self::NOON - 3600, '203.0.113.0/24', self::CHROME_WINDOWS, stepUp: LoginHistory::STEP_UP_REFUSED),
			$this->login(self::NOON - 7200, '203.0.113.0/24', self::CHROME_WINDOWS, stepUp: LoginHistory::STEP_UP_ALLOWED),
			$this->login(self::NOON - SignInHabits::WINDOW - 60, '203.0.113.0/24', self::CHROME_WINDOWS),
			$this->login(self::NOON + 60, '203.0.113.0/24', self::CHROME_WINDOWS),
			$this->login(self::NOON, '203.0.113.0/24', self::CHROME_WINDOWS),
			$this->login(self::NOON - 86400, '198.51.100.0/24', self::FIREFOX_LINUX, stepUp: LoginHistory::STEP_UP_CONFIRMED),
		], complete: self::NOON - 2 * SignInHabits::WINDOW);

		$this->assertSame([SignInHabits::NEW_NETWORK, SignInHabits::NEW_DEVICE], $habits->labels(self::NOON, '203.0.113.0/24', self::CHROME_WINDOWS, false, true));
	}

	public function testNothingNewIsClaimedBeforeTheFirstLoginOrWhereTheHistoryIsCutShort(): void {
		$this->assertSame([], $this->habits([])->labels(self::NOON, '203.0.113.0/24', self::CHROME_WINDOWS, false, true));

		$cut = $this->habits([
			$this->login(self::NOON - 86400, '198.51.100.0/24', self::FIREFOX_LINUX),
		], complete: self::NOON - 86400 * 2);
		$this->assertSame([], $cut->labels(self::NOON, '203.0.113.0/24', self::CHROME_WINDOWS, false, true));
		$this->assertSame([SignInHabits::USUAL_NETWORK], $cut->labels(self::NOON, '198.51.100.0/24', self::CHROME_WINDOWS, false, true), 'What was seen is still usual');
	}

	public function testAnHourFarFromEveryEarlierLoginOfAPersonIsUnusual(): void {
		$logins = [];
		for ($day = 1; $day <= SignInHabits::MIN_HOUR_BASELINE; $day++) {
			// Between 08:30 and 10:30 UTC.
			$logins[] = $this->login(self::NOON - $day * 86400 - 3 * 3600 + ($day % 3) * 3600 - 1800, '198.51.100.0/24', self::FIREFOX_LINUX);
		}
		$habits = $this->habits($logins);

		$threeAm = self::NOON - 9 * 3600;
		$this->assertSame([SignInHabits::USUAL_NETWORK, SignInHabits::UNUSUAL_HOUR], $habits->labels($threeAm, '198.51.100.0/24', self::FIREFOX_LINUX, false, true));
		$this->assertSame([SignInHabits::USUAL_NETWORK], $habits->labels($threeAm, '198.51.100.0/24', self::FIREFOX_LINUX, false, false), 'An app has no hour');
		$this->assertSame([SignInHabits::USUAL_NETWORK], $habits->labels(self::NOON - 30 * 60, '198.51.100.0/24', self::FIREFOX_LINUX, false, true), 'Within an hour of 10:30');

		$fewer = $this->habits(array_slice($logins, 1));
		$this->assertSame([SignInHabits::USUAL_NETWORK], $fewer->labels($threeAm, '198.51.100.0/24', self::FIREFOX_LINUX, false, true), 'Too few logins to tell');
	}

	public function testTheHourIsTheUsersOwn(): void {
		$logins = [];
		for ($day = 1; $day <= SignInHabits::MIN_HOUR_BASELINE; $day++) {
			$logins[] = $this->login(self::NOON - $day * 86400, '198.51.100.0/24', self::FIREFOX_LINUX);
		}
		// Noon UTC is 21:00 in Tokyo, 23:00 is 08:00 there: far from 21:00 in both zones.
		$tokyo = new SignInHabits($logins, [], new \DateTimeZone('Asia/Tokyo'), 0);
		$this->assertContains(SignInHabits::UNUSUAL_HOUR, $tokyo->labels(self::NOON + 11 * 3600, '198.51.100.0/24', self::FIREFOX_LINUX, false, true));
		// Midnight wraps: 23:30 is near 00:10.
		$late = [];
		for ($day = 1; $day <= SignInHabits::MIN_HOUR_BASELINE; $day++) {
			$late[] = $this->login(self::NOON - $day * 86400 + 12 * 3600 + 600, '198.51.100.0/24', self::FIREFOX_LINUX);
		}
		$this->assertNotContains(SignInHabits::UNUSUAL_HOUR, $this->habits($late)->labels(self::NOON + 11 * 3600 + 1800, '198.51.100.0/24', self::FIREFOX_LINUX, false, true));
	}

	/**
	 * @param list<LoginHistoryEntry> $logins
	 * @param list<string> $trusted
	 */
	private function habits(array $logins, array $trusted = [], int $complete = 0): SignInHabits {
		return new SignInHabits($logins, $trusted, new \DateTimeZone('UTC'), $complete);
	}

	private function login(int $at, string $netKey, string $userAgent, ?string $stepUp = null, string $method = LoginHistory::METHOD_PASSWORD): LoginHistoryEntry {
		return new LoginHistoryEntry((string)++$this->id, 'alice', $at, null, $netKey, $userAgent, $method, false, LoginHistory::CONFIRMED_BY_NONE, $stepUp, null);
	}
}
