<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\DB\ConnectionAdapter;
use OCA\IntrusionDetection\Address\AddressCache;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Blocklist\SourceRepository;
use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Cache\CountBuffer;
use OCA\IntrusionDetection\Cache\KeyLock;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\Checks\AccountUnderAttack\AccountUnderAttackDetector;
use OCA\IntrusionDetection\Check\Checks\BlocklistMatch\BlocklistMatchDetector;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffing\CredentialStuffingDetector;
use OCA\IntrusionDetection\Check\Checks\PasswordSpraying\PasswordSprayingDetector;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Detection\AttemptCounters;
use OCA\IntrusionDetection\Detection\AttemptRecord;
use OCA\IntrusionDetection\Detection\AttemptRecorder;
use OCA\IntrusionDetection\Detection\Cooldown;
use OCA\IntrusionDetection\Detection\DetectionAccounts;
use OCA\IntrusionDetection\Detection\DetectionHits;
use OCA\IntrusionDetection\Detection\DetectionService;
use OCA\IntrusionDetection\Detection\DetectionTotals;
use OCA\IntrusionDetection\Event\TypedEvents;
use OCA\IntrusionDetection\Listener\FailedLoginListener;
use OCA\IntrusionDetection\Login\EmailAccounts;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\ServerAddresses;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Personal\FailedLoginStats;
use OCA\IntrusionDetection\Response\BanService;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCA\IntrusionDetection\Risk\RiskScorer;
use OCA\IntrusionDetection\State\AppState;
use OCA\IntrusionDetection\State\HotState;
use OCA\IntrusionDetection\Tests\Unit\Cache\ClockedCache;
use OCA\IntrusionDetection\Tests\Unit\Cache\FixedCaches;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IDBConnection;
use OCP\IUserManager;
use OCP\Server;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * Failed logins through the detectors that cool down and count cheaply,
 * on memory caches the test chooses, with a clock it can move forward.
 */
abstract class FailedLoginCostTestCase extends LoginFailureTestCase {
	/** Seconds added to the clock of the attempts and the detections */
	protected int $offset = 0;
	protected ITimeFactory $clock;
	protected ?Cooldown $cooldown = null;
	protected ?Caches $caches = null;
	protected ?AttemptCounters $counters = null;

	protected function setUp(): void {
		parent::setUp();
		$clock = $this->createMock(ITimeFactory::class);
		$clock->method('getTime')->willReturnCallback(fn (): int => time() + $this->offset);
		$this->clock = $clock;
	}

	/**
	 * @param 'distributed'|'local' $kind
	 */
	protected static function memoryCaches(string $kind): Caches {
		// Kept across requests like Redis or APCu; nothing expires within a test.
		return new FixedCaches(new ClockedCache(static fn (): int => 0), null, $kind === 'distributed');
	}

	/**
	 * Write the counts that wait in the memory cache, as the flush does once
	 * their minutes are over.
	 */
	protected function flushCounts(): void {
		if ($this->caches === null) {
			return;
		}
		$later = $this->createMock(ITimeFactory::class);
		$later->method('getTime')->willReturnCallback(fn (): int => $this->clock->getTime() + 2 * CountBuffer::PERIOD);
		$buffer = new CountBuffer($this->caches, $later, Server::get(LoggerInterface::class), Server::get(Fingerprinter::class));
		$buffer->flush([(new DetectionHits(Server::get(DetectionMapper::class), $buffer))->writeCounts(...)]);
	}

	/**
	 * Rebuild the failed-login listener with the detectors that cool down
	 * and count cheaply, the detection service and the lock on these caches,
	 * and the clock. Counted: the counters bound the counts from the start.
	 */
	protected function useCaches(Caches $caches, bool $counted = false): void {
		$this->caches = $caches;
		$hits = new DetectionHits(Server::get(DetectionMapper::class), new CountBuffer($caches, $this->clock, Server::get(LoggerInterface::class), Server::get(Fingerprinter::class)));
		$this->cooldown = new Cooldown($caches, Server::get(DetectionMapper::class), $hits);
		$counters = new AttemptCounters($caches);
		if ($counted) {
			// Counting started a window ago, so that the counters bound the counts.
			$counters->count(new AttemptRecord(AttemptKind::PasswordLogin, SourceKey::fromIp('192.0.2.254'), null, null, null, null, [], $this->clock->getTime() - AttemptCounters::WINDOW - 1, true));
		}
		$this->counters = $counters;
		$service = new DetectionService(
			Server::get(DetectionMapper::class),
			Server::get(CheckRegistry::class),
			$this->checkSettings(),
			$this->clock,
			Server::get(RiskScorer::class),
			Server::get(DetectionAccounts::class),
			Server::get(DetectionTotals::class),
			new KeyLock($caches),
			Server::get(Fingerprinter::class),
			$hits,
		);
		$engine = new ResponseEngine(
			Server::get(CheckRegistry::class),
			$this->checkSettings(),
			$service,
			Server::get(ContainerInterface::class),
			Server::get(TypedEvents::class),
			Server::get(AuditLogger::class),
			Server::get(LoggerInterface::class),
		);
		$addresses = new RemoteAddressResolver($this->request, $this->throttler(), Server::get(ServerAddresses::class));
		$this->listener = new FailedLoginListener(
			$this->appSettings(),
			$addresses,
			$this->dispatcher([
				BlocklistMatchDetector::class => new BlocklistMatchDetector($addresses, $this->requestContext, Server::get(AddressCache::class), Server::get(SourceRepository::class)),
				CredentialStuffingDetector::class => new CredentialStuffingDetector(
					$this->checkSettings(),
					$this->attempts,
					Server::get(FlaggedSources::class),
					Server::get(BanService::class),
					$addresses,
					Server::get(Caches::class),
					Server::get(RiskScorer::class),
					Server::get(AppState::class),
					$this->cooldown,
					$counters,
				),
				PasswordSprayingDetector::class => new PasswordSprayingDetector(
					$this->checkSettings(),
					$this->attempts,
					Server::get(FlaggedSources::class),
					Server::get(Fingerprinter::class),
					Server::get(Caches::class),
					Server::get(RiskScorer::class),
					$counters,
				),
				AccountUnderAttackDetector::class => new AccountUnderAttackDetector(
					$this->checkSettings(),
					$this->attempts,
					Server::get(RiskScorer::class),
					$this->cooldown,
					Server::get(BanService::class),
					$counters,
				),
			], $engine),
			new AttemptRecorder($this->attempts, Server::get(Fingerprinter::class), $this->clock, Server::get(HotState::class), $counters),
			Server::get(RiskScorer::class),
			Server::get(IUserManager::class),
			$this->request,
			Server::get(LoggerInterface::class),
			Server::get(FailedLoginStats::class),
			Server::get(EmailAccounts::class),
		);
	}

	protected function queriesFor(\Closure $action): int {
		$connection = Server::get(IDBConnection::class);
		$this->assertInstanceOf(ConnectionAdapter::class, $connection);
		$before = $connection->getInner()->getStats()['executed'];
		$action();
		return $connection->getInner()->getStats()['executed'] - $before;
	}
}
