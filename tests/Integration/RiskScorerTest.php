<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\DB\ConnectionAdapter;
use OC\Memcache\ArrayCache;
use OCA\IntrusionDetection\Address\AddressCache;
use OCA\IntrusionDetection\Address\Verdict;
use OCA\IntrusionDetection\Check\Checks\ReservedName;
use OCA\IntrusionDetection\Check\Checks\TrapUrl;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Db\AttemptMapper;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Guard\RequestContext;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\Risk\AttackTools;
use OCA\IntrusionDetection\Risk\RiskAssessment;
use OCA\IntrusionDetection\Risk\RiskScorer;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\ICacheFactory;
use OCP\IDBConnection;
use OCP\IRequest;
use OCP\Security\Bruteforce\IThrottler;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;

/**
 * The address risk score (concept section 10.18): each fact, the bounds,
 * the tiers, the cache, and that it costs nothing where it cannot change a
 * decision.
 */
#[Group('DB')]
class RiskScorerTest extends IntegrationTestCase {
	private const IP = '198.51.100.7';

	private Settings $settings;
	private RequestContext $context;
	private ?ArrayCache $memory = null;

	protected function setUp(): void {
		parent::setUp();
		$this->settings = Server::get(Settings::class);
		$this->settings->setGlobal(GlobalSettings::RISK_ENABLED, true);
		$this->context = new RequestContext();
	}

	public function testAnAddressWithoutFactsScoresZero(): void {
		$risk = $this->scorer()->score(SourceKey::fromIp(self::IP));
		$this->assertSame(0, $risk->score);
		$this->assertSame([], $risk->parts);
		$this->assertSame(RiskAssessment::TIER_NORMAL, $risk->tier);
	}

	public function testAnAttackToolOnAFailedLoginCountsForADay(): void {
		$source = SourceKey::fromIp(self::IP);
		$scorer = $this->scorer();
		$scorer->noteFailedLogin($source, 'Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0');
		$this->assertSame([], $scorer->score($source)->parts, 'A browser is not a tool');
		$scorer->noteFailedLogin($source, 'sqlmap/1.7.2#stable');
		$this->assertSame([['fact' => RiskAssessment::FACT_ATTACK_TOOL, 'points' => 2, 'detail' => 'sqlmap']], $scorer->score($source)->parts);
		$this->assertSame([], $this->scorer()->score(SourceKey::fromIp('198.51.100.8'))->parts, 'Only for that address');
	}

	public function testCustomAttackToolsCount(): void {
		$this->settings->setGlobal(GlobalSettings::RISK_ATTACK_TOOL_PATTERNS, ['evilscan']);
		$source = SourceKey::fromIp(self::IP);
		$this->scorer()->noteFailedLogin($source, 'EvilScan/2');
		$this->assertSame('evilscan', $this->scorer()->score($source)->parts[0]['detail'] ?? null);
	}

	public function testNetworkAttributesComeFromTheVerdictOfTheRequest(): void {
		$this->context->setVerdict(new Verdict(0, '', ['tor', 'net:exits', 'hosting', 'net:aws', 'list:watch']));
		$risk = $this->scorer()->score(SourceKey::fromIp(self::IP));
		$this->assertSame([
			['fact' => RiskAssessment::FACT_TOR, 'points' => 2, 'detail' => null],
			['fact' => RiskAssessment::FACT_HOSTING, 'points' => 1, 'detail' => null],
			['fact' => RiskAssessment::FACT_BLOCKLIST, 'points' => 2, 'detail' => 'watch'],
		], $risk->parts);
		$this->assertSame(5, $risk->score);
		$this->assertSame(RiskAssessment::TIER_HIGH, $risk->tier);

		$other = $this->scorer()->score(SourceKey::fromIp('198.51.100.8'));
		$this->assertSame([], $other->parts, 'The request\'s verdict is not another address\'s');
	}

	public function testAnotherAddressUsesItsCachedVerdictWithoutALookup(): void {
		$this->memory = new ArrayCache();
		$source = SourceKey::fromIp('198.51.100.8');
		$this->addressCache()->set($source, new Verdict(0, '', ['hosting', 'net:aws'], time() + 300), time());
		$queries = $this->queries();
		$risk = $this->scorer()->score($source);
		$this->assertSame([['fact' => RiskAssessment::FACT_HOSTING, 'points' => 1, 'detail' => null]], $risk->parts);
		$this->assertSame(3, $this->queries() - $queries, 'The three stored facts, but no address lookup');
	}

	public function testOnlyEnforcedTrapHitsCount(): void {
		$this->detection(TrapUrl::ID, self::IP, time(), enforced: false);
		$this->assertSame([], $this->scorer()->score(SourceKey::fromIp(self::IP))->parts, 'Observed while learning or in Observe mode: nothing was blocked, so it scores nothing');
	}

	public function testATrapOrReservedNameHitCountsFor24Hours(): void {
		$this->detection(TrapUrl::ID, self::IP, time() - 3600);
		$this->assertSame([['fact' => RiskAssessment::FACT_TRAP, 'points' => 3, 'detail' => 'trap_url']], $this->scorer()->score(SourceKey::fromIp(self::IP))->parts);

		$this->detection(ReservedName::ID, '198.51.100.9', time() - RiskScorer::TRAP_WINDOW - 60);
		$this->assertSame([], $this->scorer()->score(SourceKey::fromIp('198.51.100.9'))->parts, 'Older than a day');

		$this->detection(ReservedName::ID, '2001:db8:1:2::77', time());
		$this->assertSame(3, $this->scorer()->score(SourceKey::fromIp('2001:db8:1:2::abc'))->score, 'IPv6 counts per /64');
		$this->assertSame(0, $this->scorer()->score(SourceKey::fromIp('2001:db8:1:3::77'))->score);
	}

	public function testAFlaggedAddressOrNetworkCounts(): void {
		$flags = Server::get(FlaggedSources::class);
		$flags->flagSource(SourceKey::fromIp(self::IP), FlaggedSources::REASON_ATTACK);
		$this->assertSame([['fact' => RiskAssessment::FACT_FLAGGED, 'points' => 2, 'detail' => 'attack']], $this->scorer()->score(SourceKey::fromIp(self::IP))->parts);
		$flags->flagNetwork(SourceKey::fromIp('203.0.113.1'), FlaggedSources::REASON_USER_DENIED);
		$this->assertSame(2, $this->scorer()->score(SourceKey::fromIp('203.0.113.200'))->score);
	}

	public function testEveryFiveFailedLoginsInTheLastHourCountUpToThreeTimes(): void {
		$expected = [4 => 0, 5 => 1, 9 => 1, 10 => 2, 15 => 3, 40 => 3];
		$stored = 0;
		foreach ($expected as $failures => $points) {
			for (; $stored < $failures; $stored++) {
				$this->attempt(self::IP, time() - 60);
			}
			$this->assertSame($points, $this->scorer()->score(SourceKey::fromIp(self::IP))->score, $failures . ' failures');
		}
		$this->attempt('198.51.100.20', time() - RiskScorer::FAILURES_WINDOW - 10);
		for ($i = 0; $i < 4; $i++) {
			$this->attempt('198.51.100.20', time());
		}
		$this->assertSame(0, $this->scorer()->score(SourceKey::fromIp('198.51.100.20'))->score, 'Older than an hour');
	}

	public function testAnOfficeNetworkTakesTenPointsOff(): void {
		$this->settings->setGlobal(GlobalSettings::RISKY_NETWORK_OFFICE_NETWORKS, ['198.51.100.0/24']);
		$this->context->setVerdict(new Verdict(0, '', ['tor', 'hosting']));
		$risk = $this->scorer()->score(SourceKey::fromIp(self::IP));
		$this->assertSame(-7, $risk->score);
		$this->assertSame(['fact' => RiskAssessment::FACT_OFFICE, 'points' => -10, 'detail' => '198.51.100.0/24'], $risk->parts[2]);
		$this->assertSame(RiskAssessment::TIER_NORMAL, $risk->tier);
	}

	public function testTheBoundsWithEveryFactAtOnce(): void {
		$source = SourceKey::fromIp(self::IP);
		$this->context->setVerdict(new Verdict(0, '', ['tor', 'hosting', 'list:a', 'list:b']));
		$this->scorer()->noteFailedLogin($source, 'hydra');
		$this->detection(TrapUrl::ID, self::IP, time());
		$this->detection(ReservedName::ID, self::IP, time());
		Server::get(FlaggedSources::class)->flagSource($source, FlaggedSources::REASON_ATTACK);
		for ($i = 0; $i < 100; $i++) {
			$this->attempt(self::IP, time());
		}
		$risk = $this->scorer()->score($source);
		$this->assertSame(15, $risk->score, '2 + 2 + 1 + 2 + 3 + 2 + 3: each fact counts once, failures at most 3');
		$this->assertCount(7, $risk->parts);
		$this->assertSame(3, $risk->lower(10), 'A quarter, rounded up');
		$this->assertSame(2, $risk->lower(5), 'Limits never go below 2');

		$this->settings->setGlobal(GlobalSettings::RISKY_NETWORK_OFFICE_NETWORKS, ['198.51.100.7']);
		$this->assertSame(5, $this->scorer()->score($source)->score);
	}

	public function testPointsTiersAndFactorsAreSettings(): void {
		$this->settings->setGlobal(GlobalSettings::RISK_POINTS_HOSTING, 5);
		$this->settings->setGlobal(GlobalSettings::RISK_TIER_HIGH, 6);
		$this->settings->setGlobal(GlobalSettings::RISK_FACTOR_ELEVATED, 0.8);
		$this->context->setVerdict(new Verdict(0, '', ['hosting']));
		$risk = $this->scorer()->score(SourceKey::fromIp(self::IP));
		$this->assertSame(5, $risk->score);
		$this->assertSame(RiskAssessment::TIER_ELEVATED, $risk->tier);
		$this->assertSame(8, $risk->lower(10));
		$this->assertSame(['elevated' => 2, 'high' => 6], $risk->toArray()['tiers'], 'The tiers in force are kept with the score');

		$this->settings->setGlobal(GlobalSettings::RISK_POINTS_HOSTING, 0);
		$this->assertSame([], $this->scorer()->score(SourceKey::fromIp(self::IP))->parts, 'A fact worth 0 points is left out');
	}

	public function testOffItIsNeutralAndAsksNothing(): void {
		$this->settings->setGlobal(GlobalSettings::RISK_ENABLED, false);
		$this->context->setVerdict(new Verdict(0, '', ['tor']));
		$source = SourceKey::fromIp(self::IP);
		$queries = $this->queries();
		$scorer = $this->scorer();
		$this->assertEquals(RiskAssessment::neutral(), $scorer->score($source));
		$scorer->noteFailedLogin($source, 'sqlmap/1.7');
		$limits = $scorer->limits($source, ['min_failures' => [10, 6]]);
		$this->assertSame(10, $limits->of('min_failures'));
		$this->assertSame(0, $this->queries() - $queries);
	}

	public function testTheStoredFactsAreCachedForAMinute(): void {
		$this->memory = new ArrayCache();
		$source = SourceKey::fromIp(self::IP);
		$this->scorer()->score($source);
		$queries = $this->queries();
		$this->scorer()->score($source);
		$this->assertSame(0, $this->queries() - $queries, 'No query within the minute');

		$this->scorer()->noteFailedLogin($source, 'nikto');
		$this->assertSame(2, $this->scorer()->score($source)->score, 'A new tool is seen at once');
	}

	public function testLimitsAskForTheScoreOnlyWhenItCanChangeTheOutcome(): void {
		$this->context->setVerdict(new Verdict(0, '', ['tor', 'hosting']));
		$source = SourceKey::fromIp(self::IP);
		$scorer = $this->scorer();

		$queries = $this->queries();
		$farBelow = $scorer->limits($source, ['min_failures' => [10, 1], 'min_names' => [5, 1]]);
		$reached = $scorer->limits($source, ['min_failures' => [10, 12], 'min_names' => [5, 6]]);
		$this->assertSame(0, $this->queries() - $queries, 'Far below the lowest limit, or at the configured one: no query');
		$this->assertNull($farBelow->risk);
		$this->assertTrue($reached->reached());
		$this->assertFalse($reached->isLowered());

		$close = $scorer->limits($source, ['min_failures' => [10, 6], 'min_names' => [5, 3]]);
		$this->assertSame(3, $this->queries() - $queries, 'In between, the score is computed');
		$this->assertTrue($close->reached(), 'Score 3 halves the limits to 5 and 3');
		$this->assertSame(['min_failures' => ['plain' => 10, 'effective' => 5], 'min_names' => ['plain' => 5, 'effective' => 3]], $close->facts()['loweredLimits']);
		$this->assertSame(3, $close->facts()['risk']['score']);
	}

	public function testAFailingLookupGivesTheNeutralScore(): void {
		$flags = $this->createMock(FlaggedSources::class);
		$flags->method('riskFlags')->willThrowException(new \RuntimeException('database gone'));
		$logger = $this->createMock(LoggerInterface::class);
		$logger->expects($this->once())->method('error');
		$scorer = new RiskScorer(
			$this->settings, $flags, Server::get(AttemptMapper::class), Server::get(DetectionMapper::class), $this->context,
			$this->addressCache(), $this->addresses(), new AttackTools(), $this->factory(), Server::get(ITimeFactory::class), $logger,
		);
		$this->assertEquals(RiskAssessment::neutral(), $scorer->score(SourceKey::fromIp(self::IP)));
	}

	private function scorer(): RiskScorer {
		return new RiskScorer(
			$this->settings,
			Server::get(FlaggedSources::class),
			Server::get(AttemptMapper::class),
			Server::get(DetectionMapper::class),
			$this->context,
			$this->addressCache(),
			$this->addresses(),
			new AttackTools(),
			$this->factory(),
			Server::get(ITimeFactory::class),
			Server::get(LoggerInterface::class),
		);
	}

	private function addresses(): RemoteAddressResolver {
		$request = $this->createMock(IRequest::class);
		$request->method('getRemoteAddress')->willReturn(self::IP);
		return new RemoteAddressResolver($request, Server::get(IThrottler::class));
	}

	private function addressCache(): AddressCache {
		return new AddressCache($this->factory(), $this->appConfig);
	}

	private function factory(): ICacheFactory {
		$factory = $this->createMock(ICacheFactory::class);
		$factory->method('isAvailable')->willReturn($this->memory !== null);
		$factory->method('isLocalCacheAvailable')->willReturn($this->memory !== null);
		$factory->method('createDistributed')->willReturnCallback(fn (): ArrayCache => $this->memory ?? new ArrayCache());
		$factory->method('createLocal')->willReturnCallback(fn (): ArrayCache => $this->memory ?? new ArrayCache());
		return $factory;
	}

	private function detection(string $checkId, string $ip, int $lastSeen, bool $enforced = true): void {
		$source = SourceKey::fromIp($ip);
		$detection = new Detection();
		$detection->setCheckId($checkId);
		$detection->setSeverity('low');
		$detection->setEnforced($enforced);
		$detection->setIp($source->ip);
		$detection->setNetKey($source->netKey);
		$detection->setExplanationData([]);
		$detection->setActionList([]);
		$detection->setCreatedAt($lastSeen - 7200);
		$detection->setLastSeenAt($lastSeen);
		$detection->setHits(1);
		Server::get(DetectionMapper::class)->insert($detection);
	}

	private function attempt(string $ip, int $at): void {
		$source = SourceKey::fromIp($ip);
		Server::get(AttemptMapper::class)->insert(AttemptKind::PasswordLogin, $source->ipKey, $source->netKey, null, null, null, null, $at);
	}

	private function queries(): int {
		$connection = Server::get(IDBConnection::class);
		$this->assertInstanceOf(ConnectionAdapter::class, $connection);
		return $connection->getInner()->getStats()['executed'];
	}
}
