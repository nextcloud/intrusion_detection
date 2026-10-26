<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\BackgroundJob\Cleanup;
use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Check\Checks\AccountUnderAttack\AccountUnderAttack;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffing\CredentialStuffing;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffing\CredentialStuffingFacts;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffing\CredentialStuffingRule;
use OCA\IntrusionDetection\Check\Checks\PasswordSpraying\PasswordSpraying;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Detection\Cooldown;
use OCA\IntrusionDetection\Tests\Unit\Cache\FixedCaches;
use OCP\Server;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;

/**
 * A check that fired cools down: the same attack ends with the same
 * detections, hits and blocks as without the cool-down, at a fraction of
 * the queries per failed login.
 */
#[Group('DB')]
class CooldownTest extends FailedLoginCostTestCase {
	protected function setUp(): void {
		parent::setUp();
		$this->settingsEditor()->setMode(PasswordSpraying::ID, Mode::Off);
	}

	/**
	 * @return array<string, array{0: 'distributed'|'local'}>
	 */
	public static function caches(): array {
		return [
			'distributed cache' => ['distributed'],
			'local cache only' => ['local'],
		];
	}

	#[DataProvider('caches')]
	public function testABotnetOnOneAccountEndsTheSameWithAndWithoutTheCoolDown(string $caches): void {
		$this->settingsEditor()->setMode(CredentialStuffing::ID, Mode::Off);
		$this->settingsEditor()->setResponses(AccountUnderAttack::ID, [ResponseType::ProtectAccount, ResponseType::Ban, ResponseType::NotifyAdmin]);

		$plain = $this->botnet(FixedCaches::none(), '198.18.');
		$cooled = $this->botnet(self::memoryCaches($caches), '198.19.');

		$this->assertSame($plain['banned'], $cooled['banned'], 'The same addresses are blocked');
		$this->assertCount(15, $cooled['banned'], 'Every address that guessed four passwords');
		$this->assertSame($plain['afterPeriod'], $cooled['afterPeriod'], 'The merge after a period adds the hits counted meanwhile, also to the administrators\' count');
		$this->assertSame($plain['hits'], $cooled['hits'], 'The hits after the last full evaluation are added later');
		$this->assertSame(0, $plain['lastSeen']);
		$this->assertSame(0, $cooled['lastSeen'], 'Last seen with the last failure');
		$this->assertSame(1, $cooled['detections']);
		$this->assertTrue($cooled['protected']);
		$this->assertLessThan(array_sum($plain['queries']), array_sum($cooled['queries']));
	}

	public function testAFailureWhileCooledCostsAFractionOfTheQueries(): void {
		$this->settingsEditor()->setMode(CredentialStuffing::ID, Mode::Off);
		$measured = [];
		foreach ([false, true] as $ban) {
			if ($ban) {
				$this->settingsEditor()->setResponses(AccountUnderAttack::ID, [ResponseType::ProtectAccount, ResponseType::Ban, ResponseType::NotifyAdmin, ResponseType::NotifyUser]);
			}
			foreach (['none', 'distributed'] as $caches) {
				$uid = $this->user('ids-cd-' . bin2hex(random_bytes(4)))->getUID();
				$this->useCaches($caches === 'none' ? FixedCaches::none() : self::memoryCaches($caches));
				for ($i = 0; $i < 20; $i++) {
					$this->storeAttempt('192.0.2.' . ($i % 10 + 1), $uid, $uid, 'seed-' . $i);
				}
				$this->failLogin('192.0.2.100', $uid, 'fires');
				$queries = [];
				for ($i = 0; $i < 40; $i++) {
					$queries[] = $this->queriesFor(fn () => $this->failLogin('198.18.' . (count($measured) * 10 + intdiv($i, 4)) . '.1', $uid, 'guess-' . $i));
				}
				$measured[($ban ? 'ban' : 'default') . '/' . $caches] = max($queries);
			}
		}
		// The failure stats of the account and the attempt; while blocking, the address's counts and its block.
		$this->assertLessThanOrEqual(3, $measured['default/distributed'], json_encode($measured));
		$this->assertLessThan($measured['default/none'] - 12, $measured['default/distributed'], json_encode($measured));
		$this->assertLessThan($measured['ban/none'] - 12, $measured['ban/distributed'], json_encode($measured));
	}

	public function testAnAddressJoiningWhileCooledIsBlockedAtOnce(): void {
		$this->settingsEditor()->setMode(CredentialStuffing::ID, Mode::Off);
		$this->settingsEditor()->setResponses(AccountUnderAttack::ID, [ResponseType::ProtectAccount, ResponseType::Ban]);
		$uid = $this->user('ids-cd-' . bin2hex(random_bytes(4)))->getUID();
		$this->useCaches(self::memoryCaches('distributed'));
		$this->attack($uid, '198.51.100.', 1, 5);
		$detection = $this->detectionsOf(AccountUnderAttack::ID)[0];
		$hits = $detection->getHits();

		$bans = Server::get(BanMapper::class);
		foreach (['first', 'second', 'third'] as $password) {
			$this->failLogin('192.0.2.77', $uid, $password);
		}
		$this->assertSame([], $bans->findActiveForKeys(['192.0.2.77'], time()), 'Three passwords are no guessing yet');
		$this->failLogin('192.0.2.77', $uid, 'fourth');
		$ban = $bans->findActiveForKeys(['192.0.2.77'], time());
		$this->assertCount(1, $ban);
		$this->assertSame((string)$detection->getId(), (string)$ban[0]->getDetectionId(), 'The block belongs to the detection');
		$this->assertSame($hits, Server::get(DetectionMapper::class)->findById((string)$detection->getId())->getHits(), 'Within the period the hits wait in the cache');
	}

	public function testObservedFailuresOnlyCount(): void {
		$this->settingsEditor()->setMode(CredentialStuffing::ID, Mode::Off);
		$this->settingsEditor()->setMode(AccountUnderAttack::ID, Mode::Observe);
		$this->settingsEditor()->setResponses(AccountUnderAttack::ID, [ResponseType::ProtectAccount, ResponseType::Ban]);
		$uid = $this->user('ids-cd-' . bin2hex(random_bytes(4)))->getUID();
		$this->useCaches(self::memoryCaches('local'));
		$this->attack($uid, '198.51.100.', 1, 8);
		$detections = $this->detectionsOf(AccountUnderAttack::ID);
		$this->assertCount(1, $detections);
		$this->assertFalse($detections[0]->isEnforced());
		$this->assertSame(32 - 17 + 1, $detections[0]->getHits(), 'Every failure from the 17th, which fired, on is a hit');
		$this->assertSame(0, $this->rows('ids_bans'));
	}

	public function testSwitchingToProtectEndsTheObservedCoolDown(): void {
		$this->settingsEditor()->setMode(CredentialStuffing::ID, Mode::Off);
		$this->settingsEditor()->setMode(AccountUnderAttack::ID, Mode::Observe);
		$uid = $this->user('ids-cd-' . bin2hex(random_bytes(4)))->getUID();
		$this->useCaches(self::memoryCaches('distributed'));
		$this->attack($uid, '198.51.100.', 1, 5);
		$this->settingsEditor()->setMode(AccountUnderAttack::ID, Mode::Protect);
		$this->failLogin('198.51.100.1', $uid, 'once-more');
		$enforced = array_filter($this->detectionsOf(AccountUnderAttack::ID), static fn (Detection $d): bool => $d->isEnforced());
		$this->assertCount(1, $enforced, 'The enforced detection does not wait for the period');
	}

	public function testTheAddressRuleOfCredentialStuffingFiresWhileTheNetworkRuleCoolsDown(): void {
		$this->settingsEditor()->setMode(AccountUnderAttack::ID, Mode::Off);
		$this->settingsEditor()->setMode(CredentialStuffing::ID, Mode::Observe);
		$this->useCaches(self::memoryCaches('distributed'));
		// 30 failures for 30 names from ten neighbours: the network rule's numbers.
		for ($i = 0; $i < 30; $i++) {
			$this->storeAttempt('198.18.5.' . ($i % 10 + 1), 'victim-' . $i);
		}
		$this->failLogin('198.18.5.20', 'target-0');
		$this->assertSame([CredentialStuffingRule::Network], $this->stuffingRules());

		for ($i = 1; $i < 9; $i++) {
			$this->failLogin('198.18.5.20', 'target-' . ($i % 5));
		}
		$this->assertSame([CredentialStuffingRule::Network], $this->stuffingRules(), 'Nine failures of the address');
		$this->failLogin('198.18.5.20', 'target-4');
		$this->assertSame([CredentialStuffingRule::Network, CredentialStuffingRule::Source], $this->stuffingRules(), 'The tenth fires the rule of the address at once');
	}

	#[DataProvider('caches')]
	public function testOneAddressStuffingInObserveEndsTheSame(string $caches): void {
		$this->settingsEditor()->setMode(AccountUnderAttack::ID, Mode::Off);
		$this->settingsEditor()->setMode(CredentialStuffing::ID, Mode::Observe);
		$results = [];
		foreach (['plain' => FixedCaches::none(), 'cooled' => self::memoryCaches($caches)] as $run => $factory) {
			$this->useCaches($factory);
			$ip = $run === 'plain' ? '198.51.100.9' : '203.0.113.9';
			for ($i = 0; $i < 40; $i++) {
				$this->failLogin($ip, 'name-' . $i);
			}
			$this->cooldown?->purge($this->clock->getTime() + 2 * Cooldown::FLUSH_SLICE);
			$detections = array_values(array_filter($this->detectionsOf(CredentialStuffing::ID), static fn (Detection $d): bool => $d->getIp() === $ip));
			$results[$run] = array_map(static fn (Detection $d): array => [CredentialStuffingFacts::fromArray($d->getExplanationData()['facts'])->rule, $d->getHits()], $detections);
		}
		$this->assertSame([[CredentialStuffingRule::Source, 31]], $results['plain']);
		$this->assertSame($results['plain'], $results['cooled']);
	}

	public function testHitsAreTakenOnce(): void {
		$cooldown = new Cooldown(self::memoryCaches('distributed'), Server::get(DetectionMapper::class));
		$this->assertSame([0, 0], $cooldown->takeHits('123'));
		$this->assertSame(0, $cooldown->purge(time()));
		$this->assertArrayHasKey(Cooldown::class, Cleanup::PURGES, 'The cleanup job adds the hits after an attack');
	}

	/**
	 * 15 addresses, each in a network of its own, guess four passwords
	 * each, with a pause longer than a period after the tenth. The attack
	 * fires on the 17th failure.
	 *
	 * @return array{banned: list<string>, afterPeriod: array{0: int, 1: int}, hits: int, lastSeen: int, detections: int, protected: bool, queries: list<int>}
	 */
	private function botnet(Caches $caches, string $prefix): array {
		$this->offset = 0;
		$uid = $this->user('ids-cd-' . bin2hex(random_bytes(4)))->getUID();
		$this->useCaches($caches);
		$bans = Server::get(BanMapper::class);
		$queries = [];
		$afterPeriod = [0, 0];
		for ($address = 1; $address <= 15; $address++) {
			if ($address === 11) {
				$this->offset = Cooldown::PERIOD + 1;
			}
			for ($guess = 1; $guess <= 4; $guess++) {
				$queries[] = $this->queriesFor(fn () => $this->failLogin($prefix . $address . '.7', $uid, 'guess-' . $address . '-' . $guess));
				if ($address === 11 && $guess === 1) {
					$detection = $this->detectionsOf(AccountUnderAttack::ID)[0];
					$afterPeriod = [$detection->getHits(), $this->alertHits()];
				}
			}
			if ($address >= 5) {
				$this->assertCount(1, $bans->findActiveForKeys([$prefix . $address . '.7'], time()), 'Blocked on its fourth password');
			}
		}
		$this->cooldown?->purge($this->clock->getTime() + 2 * Cooldown::FLUSH_SLICE);
		$detections = array_values(array_filter($this->detectionsOf(AccountUnderAttack::ID), static fn (Detection $d): bool => $d->getUid() === $uid));
		$banned = [];
		for ($address = 1; $address <= 15; $address++) {
			if ($bans->findActiveForKeys([$prefix . $address . '.7'], time()) !== []) {
				$banned[] = (string)$address;
			}
		}
		$result = [
			'banned' => $banned,
			'afterPeriod' => $afterPeriod,
			'hits' => $detections[0]->getHits(),
			'lastSeen' => $detections[0]->getLastSeenAt() - $this->lastAttempt(),
			'detections' => count($detections),
			'protected' => $this->rows('ids_protected_accounts') > 0,
			'queries' => $queries,
		];
		// The next run starts with nothing of this one.
		foreach (['ids_detections', 'ids_alerts', 'ids_protected_accounts', 'ids_attempts'] as $table) {
			$this->db->getQueryBuilder()->delete($table)->executeStatement();
		}
		return $result;
	}

	private function attack(string $uid, string $prefix, int $from, int $to): void {
		for ($address = $from; $address <= $to; $address++) {
			for ($guess = 1; $guess <= 4; $guess++) {
				$this->failLogin($prefix . $address, $uid, 'guess-' . $address . '-' . $guess);
			}
		}
	}

	private function lastAttempt(): int {
		$qb = $this->db->getQueryBuilder();
		$qb->select($qb->func()->max('created_at'))->from('ids_attempts');
		$result = $qb->executeQuery();
		$last = (int)$result->fetchOne();
		$result->closeCursor();
		return $last;
	}

	private function alertHits(): int {
		$qb = $this->db->getQueryBuilder();
		$qb->select($qb->func()->sum('hits'))->from('ids_alerts')->where($qb->expr()->eq('check_id', $qb->createNamedParameter(AccountUnderAttack::ID)));
		$result = $qb->executeQuery();
		$sum = (int)$result->fetchOne();
		$result->closeCursor();
		return $sum;
	}

	/**
	 * @return list<CredentialStuffingRule>
	 */
	private function stuffingRules(): array {
		$rules = array_map(static fn (Detection $d): ?CredentialStuffingRule => CredentialStuffingFacts::fromArray($d->getExplanationData()['facts'])->rule, $this->detectionsOf(CredentialStuffing::ID));
		usort($rules, static fn (?CredentialStuffingRule $a, ?CredentialStuffingRule $b): int => strcmp((string)$a?->value, (string)$b?->value));
		return array_values(array_filter($rules));
	}
}
