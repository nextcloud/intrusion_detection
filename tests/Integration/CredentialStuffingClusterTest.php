<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use Doctrine\DBAL\Logging\DebugStack;
use OC\AppConfig;
use OC\DB\ConnectionAdapter;
use OC\Memcache\ArrayCache;
use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffing;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffingDetector;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Db\AttemptMapper;
use OCA\IntrusionDetection\Detection\AttemptRecord;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\State\AppState;
use OCA\IntrusionDetection\Tests\Unit\Cache\FixedCaches;
use OCP\IAppConfig;
use OCP\Server;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;

/**
 * The instance-wide part of the credential stuffing check on several web
 * servers at once: each with its own memory caches and its own copy of the
 * app config, all with the same database.
 */
#[Group('DB')]
class CredentialStuffingClusterTest extends LoginFailureTestCase {
	private const SERVERS = 3;

	private ArrayCache $distributed;
	private int $now;

	protected function setUp(): void {
		parent::setUp();
		$this->distributed = new ArrayCache('distributed');
		// A time early in a period, so that the period cannot end during the test.
		$this->now = intdiv(time(), CredentialStuffingDetector::EVALUATE_EVERY) * CredentialStuffingDetector::EVALUATE_EVERY + 1;
		$this->settingsEditor()->setParam(CredentialStuffing::ID, 'min_failures', 1000);
	}

	protected function tearDown(): void {
		// The servers wrote past this process's copy of the app config, which the reset reads.
		$this->appConfig->clearCache();
		parent::tearDown();
	}

	/**
	 * @return array<string, array{0: 'distributed'|'local'|'none'}>
	 */
	public static function caches(): array {
		return [
			'distributed cache' => ['distributed'],
			'local cache only' => ['local'],
			'no memory cache' => ['none'],
		];
	}

	#[DataProvider('caches')]
	public function testServersFailingAtTheSameMomentCountTheInstanceOncePerPeriod(string $caches): void {
		// 150 failures from 10 addresses: below the 20 addresses of a botnet.
		for ($i = 0; $i < 150; $i++) {
			$this->storeAttempt('192.0.2.' . ($i % 10 + 1), 'victim' . ($i % 30), at: $this->now - 60);
		}
		$servers = $this->servers($caches);

		$this->assertSame(1, $this->instanceQueries(fn () => $this->failOnEach($servers, $this->now)), 'One server counts for all');
		$this->assertSame(0, $this->instanceQueries(fn () => $this->failOnEach($servers, $this->now + 20)), 'Not again within the period');
		$this->assertSame(1, $this->instanceQueries(fn () => $this->failOnEach($servers, $this->now + CredentialStuffingDetector::EVALUATE_EVERY)), 'Once more in the next period');
	}

	#[DataProvider('caches')]
	public function testABotnetIsRecordedOnceAndTheVerdictReachesEveryServer(string $caches): void {
		for ($i = 0; $i < 120; $i++) {
			$this->storeAttempt('192.0.2.' . ($i % 25 + 1), 'victim' . ($i % 25), at: $this->now - 60);
		}
		$this->failOnEach($this->servers($caches), $this->now);

		$distributed = array_filter(
			$this->detectionsOf(CredentialStuffing::ID),
			static fn ($d): bool => ($d->getExplanationData()['facts']['distributed'] ?? false) === true,
		);
		$this->assertCount(1, $distributed);
		$facts = array_values($distributed)[0]->getExplanationData()['facts'];
		$this->assertSame(120, $facts['failures']);
		$this->assertSame(25, $facts['sources']);
		$this->assertSame($this->now + CredentialStuffingDetector::DISTRIBUTED_WINDOW, Server::get(AppState::class)->getInt(CredentialStuffingDetector::DISTRIBUTED_UNTIL_STATE));
	}

	#[DataProvider('caches')]
	public function testABotnetStartingDuringAPeriodIsNoticedInTheNext(string $caches): void {
		$servers = $this->servers($caches);
		$this->failOnEach($servers, $this->now);

		for ($i = 0; $i < 120; $i++) {
			$this->storeAttempt('192.0.2.' . ($i % 25 + 1), 'victim' . ($i % 25), at: $this->now + 5);
		}
		$this->failOnEach($servers, $this->now + 10);
		$this->assertSame(0, Server::get(AppState::class)->getInt(CredentialStuffingDetector::DISTRIBUTED_UNTIL_STATE), 'Not counted again within the period');

		$next = $this->now + CredentialStuffingDetector::EVALUATE_EVERY;
		$this->failOnEach($servers, $next);
		$this->assertSame($next + CredentialStuffingDetector::DISTRIBUTED_WINDOW, Server::get(AppState::class)->getInt(CredentialStuffingDetector::DISTRIBUTED_UNTIL_STATE));
	}

	public function testAPeriodIsClaimedOnceAndNeverAfterALaterOne(): void {
		$state = Server::get(AppState::class);
		$this->assertTrue($state->claim('test', 9), 'The first claim creates the row');
		$this->assertFalse($state->claim('test', 9));
		$this->assertTrue($state->claim('test', 10), 'One more digit still compares as a larger number');
		$this->assertFalse($state->claim('test', 9), 'A server whose clock is behind');
		$this->assertFalse($state->claim('test', 10));
		$this->assertTrue($state->claim('other', 9), 'Each name has its own periods');
	}

	public function testABoundedCountDecidesDuringAnAttack(): void {
		$minFailures = 100;
		for ($i = 0; $i < 300; $i++) {
			$this->storeAttempt('192.0.2.' . ($i % 25 + 1), 'victim' . ($i % 25), at: $this->now - 60);
		}
		$since = $this->now - CredentialStuffingDetector::DISTRIBUTED_WINDOW;
		$this->assertTrue($this->attempts->instanceReaches(CredentialStuffingDetector::KINDS, $since, $minFailures, 20, 20));
		$this->assertFalse($this->attempts->instanceReaches(CredentialStuffingDetector::KINDS, $since, $minFailures, 26, 20), 'Only 25 addresses');
		$this->assertFalse($this->attempts->instanceReaches(CredentialStuffingDetector::KINDS, $since, 301, 20, 20), 'Only 300 failures');
		$this->assertFalse($this->attempts->instanceReaches([AttemptKind::PasswordReset], $since, 10, 2, 2), 'Other kinds only');
		$this->assertFalse($this->attempts->instanceReaches(CredentialStuffingDetector::KINDS, $this->now, 10, 2, 2), 'Too old');
	}

	public function testBeyondTheBoundedCountAllAttemptsDecide(): void {
		$rows = AttemptMapper::SAMPLE_ROWS + 1;
		$this->db->beginTransaction();
		for ($i = 0; $i < $rows; $i++) {
			$this->attempts->insert(AttemptKind::PasswordLogin, 'ip' . $i, 'net', 'name', null, null, null, $this->now - 60);
		}
		$this->db->commit();
		$since = $this->now - CredentialStuffingDetector::DISTRIBUTED_WINDOW;
		// Any SAMPLE_ROWS of the attempts come from one address fewer than all of them.
		$this->assertTrue($this->attempts->instanceReaches(CredentialStuffingDetector::KINDS, $since, 10, $rows, 1));
		$this->assertFalse($this->attempts->instanceReaches(CredentialStuffingDetector::KINDS, $since, 10, $rows + 1, 1));
	}

	/**
	 * @param list<CredentialStuffingDetector> $servers
	 */
	private function failOnEach(array $servers, int $time): void {
		$fingerprinter = Server::get(Fingerprinter::class);
		foreach ($servers as $n => $detector) {
			$detector->detect(new AttemptRecord(
				AttemptKind::PasswordLogin,
				SourceKey::fromIp('198.51.100.' . ($n + 1)),
				bin2hex($fingerprinter->name('someone' . $n)),
				null,
				null,
				null,
				[],
				$time,
				true,
			), null);
		}
	}

	/**
	 * Web servers handling requests at the same moment. Each has read the
	 * app config before any of them changed it, as concurrent requests do.
	 *
	 * @param 'distributed'|'local'|'none' $caches
	 * @return list<CredentialStuffingDetector>
	 */
	private function servers(string $caches): array {
		$servers = [];
		for ($n = 0; $n < self::SERVERS; $n++) {
			$local = new ArrayCache('local' . $n);
			$memory = match ($caches) {
				'distributed' => new FixedCaches($this->distributed, $local, true),
				'local' => new FixedCaches($local, $local),
				default => FixedCaches::none(),
			};

			$appConfig = $this->build(AppConfig::class, []);
			$appSettings = $this->build(AppSettings::class, [IAppConfig::class => $appConfig]);
			$servers[] = $this->build(CredentialStuffingDetector::class, [
				Caches::class => $memory,
				AppSettings::class => $appSettings,
				CheckSettings::class => $this->build(CheckSettings::class, [IAppConfig::class => $appConfig, AppSettings::class => $appSettings]),
			]);
		}
		return $servers;
	}

	/**
	 * @template T of object
	 * @param class-string<T> $class
	 * @param array<string, object> $overrides
	 * @return T
	 */
	private function build(string $class, array $overrides): object {
		$args = [];
		foreach ((new \ReflectionClass($class))->getConstructor()?->getParameters() ?? [] as $parameter) {
			$type = $parameter->getType();
			$this->assertInstanceOf(\ReflectionNamedType::class, $type);
			$args[] = $overrides[$type->getName()] ?? Server::get($type->getName());
		}
		return new $class(...$args);
	}

	/**
	 * How many instance-wide counts over the attempts the work ran: those
	 * that filter on no address, network or name.
	 */
	private function instanceQueries(\Closure $work): int {
		$db = Server::get(\OCP\IDBConnection::class);
		$this->assertInstanceOf(ConnectionAdapter::class, $db);
		$configuration = $db->getInner()->getConfiguration();
		$previous = $configuration->getSQLLogger();
		$log = new DebugStack();
		$configuration->setSQLLogger($log);
		try {
			$work();
		} finally {
			$configuration->setSQLLogger($previous);
		}
		return count(array_filter($log->queries, static fn (array $query): bool => str_contains((string)$query['sql'], 'ids_attempts')
			&& str_contains((string)$query['sql'], 'COUNT(DISTINCT')
			&& preg_match('/[`"](ip_key|net_key|pw_fp|uid|share_id|name_hmac)[`"]\s*(IN|=)/i', (string)$query['sql']) !== 1));
	}
}
