<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\Memcache\ArrayCache;
use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Cache\KeyLock;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\Checks\ManualBlock\ManualBlock;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Detection\DetectionAccounts;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Detection\DetectionService;
use OCA\IntrusionDetection\Detection\DetectionTotals;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Risk\RiskScorer;
use OCA\IntrusionDetection\Tests\Unit\Cache\FixedCaches;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * Parallel hits of one attack are recorded one after the other.
 */
#[Group('DB')]
class DetectionLockTest extends IntegrationTestCase {
	/** @var list<string> */
	private array $locked = [];

	private function service(?Caches $factory = null): DetectionService {
		$locked = &$this->locked;
		$cache = new class($locked) extends ArrayCache {
			/** @param list<string> $log */
			public function __construct(
				private array &$log,
			) {
				parent::__construct();
			}

			public function add($key, $value, $ttl = 0) {
				$this->log[] = 'acquire ' . $key . ' ' . $ttl;
				return parent::add($key, $value, $ttl);
			}

			public function remove($key) {
				$this->log[] = 'release ' . $key;
				return parent::remove($key);
			}
		};
		if ($factory === null) {
			$factory = new FixedCaches($cache);
		}
		return new DetectionService(
			Server::get(DetectionMapper::class),
			Server::get(CheckRegistry::class),
			$this->checkSettings(),
			Server::get(ITimeFactory::class),
			Server::get(RiskScorer::class),
			Server::get(DetectionAccounts::class),
			Server::get(DetectionTotals::class),
			new KeyLock($factory),
		);
	}

	public function testAMergingDetectionIsRecordedUnderALockPerMergeKey(): void {
		$protect = new ModeState(Mode::Protect, Mode::Protect);
		$draft = new DetectionDraft(ManualBlock::ID, SourceKey::fromIp('198.51.100.7'), merge: DetectionDraft::MERGE_SOURCE);
		$service = $this->service();
		[$first] = $service->record($draft, $protect);
		[$second, $new] = $service->record($draft, $protect);
		$this->assertFalse($new);
		$this->assertSame($first->getId(), $second->getId());
		$this->assertSame(2, $second->getHits());
		$path = 'detection/' . md5((string)$draft->mergeKey());
		$this->assertSame(['acquire ' . $path . ' ' . KeyLock::TTL, 'release ' . $path, 'acquire ' . $path . ' ' . KeyLock::TTL, 'release ' . $path], $this->locked);
	}

	public function testADetectionThatNeverMergesTakesNoLock(): void {
		$this->service()->record(new DetectionDraft(ManualBlock::ID, SourceKey::fromIp('198.51.100.7')), new ModeState(Mode::Protect, Mode::Protect));
		$this->assertSame([], $this->locked);
	}

	public function testWithoutAMemoryCacheAMergedHitTakesNoLockAndWritesNoLockRows(): void {
		$protect = new ModeState(Mode::Protect, Mode::Protect);
		$draft = new DetectionDraft(ManualBlock::ID, SourceKey::fromIp('198.51.100.8'), merge: DetectionDraft::MERGE_SOURCE);
		$service = $this->service(FixedCaches::none());
		$service->record($draft, $protect);
		$before = $this->db->getInner()->getStats()['executed'];
		[$merged, $new] = $service->record($draft, $protect);
		$this->assertFalse($new);
		$this->assertSame(2, $merged->getHits());
		// The merge target and the update; core's database locking would add three writes.
		$this->assertSame(2, $this->db->getInner()->getStats()['executed'] - $before);
		$this->assertSame([], $this->locked);
	}
}
