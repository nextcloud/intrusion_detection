<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\Memcache\ArrayCache;
use OCA\IntrusionDetection\Check\Checks\AccountUnderAttack\AccountUnderAttack;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffing\CredentialStuffing;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffing\CredentialStuffingFacts;
use OCA\IntrusionDetection\Check\Checks\PasswordSpraying\PasswordSpraying;
use OCA\IntrusionDetection\Check\Checks\PasswordSpraying\PasswordSprayingFacts;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Detection\AttemptCounters;
use OCA\IntrusionDetection\Detection\AttemptRecord;
use OCA\IntrusionDetection\Detection\Cooldown;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Tests\Unit\Cache\FixedCaches;
use PHPUnit\Framework\Attributes\Group;

/**
 * The counts over the attempts table run only once the cheap bound in
 * the distributed cache can reach a limit: the same detections, fewer
 * queries per failed login.
 */
#[Group('DB')]
class AttemptCountersTest extends FailedLoginCostTestCase {
	private const NOW = 1_800_000_000;

	public function testTheBoundHoldsEveryFailedLoginOfTheWindow(): void {
		$counters = new AttemptCounters(new FixedCaches(new ArrayCache(), null, true));
		$address = SourceKey::fromIp('198.51.100.7');
		$counters->count(self::attempt($address, self::NOW - 10));
		$this->assertNull($counters->bound('ip_key', [$address->ipKey], self::NOW), 'Counting started just now');
		$this->assertTrue($counters->mayReach('ip_key', [$address->ipKey], self::NOW, 1000), 'Without a bound, every count is made');

		$counters = new AttemptCounters(new FixedCaches(new ArrayCache(), null, true));
		$counters->count(self::attempt(SourceKey::fromIp('192.0.2.1'), self::NOW - 2 * AttemptCounters::WINDOW - 1));
		foreach ([self::NOW - 3500, self::NOW - 100, self::NOW - 1] as $at) {
			$counters->count(self::attempt($address, $at));
		}
		$counters->count(self::attempt($address, self::NOW - 2, AttemptKind::AppPassword));
		$counters->count(self::attempt($address, self::NOW - 3, AttemptKind::UnknownShareToken));
		$counters->count(self::attempt($address, self::NOW - 4, stored: false));
		$bound = $counters->bound('ip_key', [$address->ipKey], self::NOW);
		$this->assertSame(4, $bound, 'Passwords and app passwords that were stored, within the window');
		$this->assertSame(4, $counters->bound('net_key', [$address->netKey], self::NOW));
		$this->assertSame(0, $counters->bound('ip_key', [SourceKey::fromIp('192.0.2.1')->ipKey], self::NOW), 'Two windows ago is outside');
		$this->assertSame(0, $counters->bound('uid', ['alice'], self::NOW));
		$this->assertFalse($counters->mayReach('ip_key', [$address->ipKey], self::NOW, 5));
		$this->assertTrue($counters->mayReach('ip_key', [$address->ipKey], self::NOW, 4));
		$this->assertSame(3, $counters->bound('pw_fp', ['fp-a', 'fp-b'], self::NOW), 'The passwords with a fingerprint among the candidates');
	}

	public function testACacheOfEachWebServerBoundsNothing(): void {
		$counters = new AttemptCounters(new FixedCaches(new ArrayCache(), null, false));
		$counters->count(self::attempt(SourceKey::fromIp('198.51.100.7'), self::NOW - 2 * AttemptCounters::WINDOW));
		$this->assertNull($counters->bound('ip_key', [SourceKey::fromIp('198.51.100.7')->ipKey], self::NOW), 'Each web server sees only its own failed logins');
		$this->assertNull((new AttemptCounters(FixedCaches::none()))->bound('ip_key', ['x'], self::NOW));
	}

	public function testEveryRuleFiresTheSameWithAndWithoutTheCounters(): void {
		$uid = $this->user('ids-ac-' . bin2hex(random_bytes(4)))->getUID();
		$plain = $this->rules(FixedCaches::none(), $uid);
		$counted = $this->rules(self::memoryCaches('distributed'), $uid);
		$this->assertSame([
			'account_under_attack|',
			'credential_stuffing|network',
			'credential_stuffing|source',
			'password_spraying|spray',
		], array_values(array_unique(array_map(static fn (string $d): string => implode('|', array_slice(explode('|', $d), 0, 2)), $plain))));
		$this->assertSame($plain, $counted);
	}

	public function testLimitsLoweredByTheRiskScoreAreNotMissed(): void {
		$this->appConfig->setValueBool('intrusion_detection', GlobalSettings::RISK_ENABLED, true);
		$this->useCaches(self::memoryCaches('distributed'), true);
		for ($i = 1; $i <= 5; $i++) {
			$this->failLogin('198.51.100.7', 'user' . $i);
		}
		$this->assertCount(1, $this->detectionsOf(CredentialStuffing::ID), '5 failures from an attack tool reach the lowered limits');
	}

	public function testALowAndSlowAttackCostsFewerQueries(): void {
		$queries = [];
		foreach (['plain' => FixedCaches::none(), 'counted' => self::memoryCaches('distributed')] as $run => $caches) {
			$this->useCaches($caches, $run === 'counted');
			$users = [];
			for ($u = 0; $u < 5; $u++) {
				$users[] = $this->user('ids-ac-' . $u . bin2hex(random_bytes(3)))->getUID();
			}
			$this->failLogin('192.0.2.250', 'warm-up');
			$counts = [];
			for ($i = 0; $i < 100; $i++) {
				$name = $i % 4 === 0 ? $users[$i % 5] : 'nobody-' . $run . '-' . $i;
				$counts[] = $this->queriesFor(fn () => $this->failLogin('172.' . ($run === 'plain' ? 16 : 17) . '.' . $i . '.1', $name, 'password-' . $run . '-' . $i));
			}
			$queries[$run] = array_sum($counts) / count($counts);
		}
		$this->assertSame([], $this->detectionsOf(CredentialStuffing::ID));
		$this->assertSame([], $this->detectionsOf(PasswordSpraying::ID));
		$this->assertSame([], $this->detectionsOf(AccountUnderAttack::ID));
		// Without the bound: a count per password, address, network and account.
		$this->assertLessThanOrEqual($queries['plain'] - 3, $queries['counted'], json_encode($queries));
	}

	/**
	 * Fire every rule that counts failed logins: a spray, one address
	 * stuffing, a network stuffing thinly, and a botnet on one account.
	 *
	 * @return list<string> check, rule and hits of each detection, with its address or account
	 */
	private function rules(FixedCaches $caches, string $uid): array {
		foreach (self::tables() as $table) {
			$this->db->getQueryBuilder()->delete($table)->executeStatement();
		}
		$this->useCaches($caches, true);
		for ($i = 1; $i <= 6; $i++) {
			$this->failLogin('203.0.113.' . $i, 'sprayed-' . $i, 'Spring2026!');
		}
		for ($i = 1; $i <= 12; $i++) {
			$this->failLogin('198.51.100.7', 'stuffed-' . $i, 'list-' . $i);
		}
		for ($i = 1; $i <= 33; $i++) {
			$this->failLogin('198.18.9.' . ($i % 11 + 1), 'thin-' . $i, 'thin-' . $i);
		}
		for ($i = 1; $i <= 12; $i++) {
			$this->failLogin('192.0.2.' . ($i % 6 + 1), $uid, 'guess-' . $i);
		}
		// The hits counted while the checks cooled down.
		$this->cooldown?->purge($this->clock->getTime() + 2 * Cooldown::FLUSH_SLICE);
		$rows = [];
		foreach ([PasswordSpraying::ID, CredentialStuffing::ID, AccountUnderAttack::ID] as $check) {
			foreach ($this->detectionsOf($check) as $detection) {
				$facts = $detection->getExplanationData()['facts'];
				$rule = match ($check) {
					PasswordSpraying::ID => PasswordSprayingFacts::fromArray($facts)->rule?->value,
					CredentialStuffing::ID => CredentialStuffingFacts::fromArray($facts)->rule?->value,
					default => '',
				};
				$rows[] = $check . '|' . $rule . '|' . ($detection->getIp() ?? $detection->getUid()) . '|' . $detection->getHits();
			}
		}
		sort($rows);
		return $rows;
	}

	private static function attempt(SourceKey $source, int $at, AttemptKind $kind = AttemptKind::PasswordLogin, bool $stored = true): AttemptRecord {
		return new AttemptRecord($kind, $source, null, null, null, $kind === AttemptKind::PasswordLogin ? 'fp-a' : null, [], $at, $stored);
	}
}
