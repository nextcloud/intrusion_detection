<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\Checks\ManualBlock;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Db\KeyLock;
use OCA\IntrusionDetection\Detection\DetectionAccounts;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Detection\DetectionService;
use OCA\IntrusionDetection\Detection\DetectionTotals;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Risk\RiskScorer;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Lock\ILockingProvider;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * Parallel hits of one attack are recorded one after the other.
 */
#[Group('DB')]
class DetectionLockTest extends IntegrationTestCase {
	/** @var list<string> */
	private array $locked = [];

	private function service(): DetectionService {
		$locks = $this->createMock(ILockingProvider::class);
		$locks->method('acquireLock')->willReturnCallback(function (string $path): void {
			$this->locked[] = 'acquire ' . $path;
		});
		$locks->method('releaseLock')->willReturnCallback(function (string $path): void {
			$this->locked[] = 'release ' . $path;
		});
		return new DetectionService(
			Server::get(DetectionMapper::class),
			Server::get(CheckRegistry::class),
			Server::get(Settings::class),
			Server::get(ITimeFactory::class),
			Server::get(RiskScorer::class),
			Server::get(DetectionAccounts::class),
			Server::get(DetectionTotals::class),
			new KeyLock($locks),
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
		$path = 'intrusion_detection/detection/' . md5((string)$draft->mergeKey());
		$this->assertSame(['acquire ' . $path, 'release ' . $path, 'acquire ' . $path, 'release ' . $path], $this->locked);
	}

	public function testADetectionThatNeverMergesTakesNoLock(): void {
		$this->service()->record(new DetectionDraft(ManualBlock::ID, SourceKey::fromIp('198.51.100.7')), new ModeState(Mode::Protect, Mode::Protect));
		$this->assertSame([], $this->locked);
	}
}
