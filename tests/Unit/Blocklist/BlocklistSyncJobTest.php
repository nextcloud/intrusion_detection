<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Blocklist;

use OCA\IntrusionDetection\BackgroundJob\BlocklistSyncJob;
use OCA\IntrusionDetection\Blocklist\BlocklistSource;
use OCA\IntrusionDetection\Blocklist\BlocklistSync;
use OCA\IntrusionDetection\Blocklist\ListFormat;
use OCA\IntrusionDetection\Blocklist\ListState;
use OCA\IntrusionDetection\Blocklist\SourceRepository;
use OCA\IntrusionDetection\Blocklist\StateStore;
use OCA\IntrusionDetection\Config\AppSettings;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\BackgroundJob\IJobList;
use Test\TestCase;

class BlocklistSyncJobTest extends TestCase {
	public function testRunsAtTheGlobalIntervalOrTheShortestListInterval(): void {
		$this->assertSame(21600, $this->job([])->getInterval());
		$this->assertSame(21600, $this->job([$this->source('a', null)], ['a' => 1])->getInterval());
		$this->assertSame(3600, $this->job([$this->source('a', null), $this->source('tor', 3600)], ['a' => 1, 'tor' => 1])->getInterval());
	}

	public function testRunsOftenWhileAListWasNeverDownloaded(): void {
		$this->assertSame(BlocklistSyncJob::MIN_INTERVAL, $this->job([$this->source('a', null)])->getInterval());
	}

	public function testWithoutListsItOnlyCleansUp(): void {
		$sync = $this->createMock(BlocklistSync::class);
		$sync->method('hasActiveSources')->willReturn(false);
		$sync->expects($this->once())->method('cleanup');
		$sync->expects($this->never())->method('syncDue');
		$this->job([], [], $sync)->start($this->createMock(IJobList::class));
	}

	public function testWithListsItSyncsWhatIsDue(): void {
		$sync = $this->createMock(BlocklistSync::class);
		$sync->method('hasActiveSources')->willReturn(true);
		$sync->expects($this->once())->method('syncDue')->willReturn([]);
		$this->job([$this->source('a', null)], ['a' => 1], $sync)->start($this->createMock(IJobList::class));
	}

	/**
	 * @param list<BlocklistSource> $enabled
	 * @param array<string, int> $attempts
	 */
	private function job(array $enabled, array $attempts = [], ?BlocklistSync $sync = null): BlocklistSyncJob {
		$sources = $this->createMock(SourceRepository::class);
		$sources->method('enabled')->willReturn($enabled);
		$states = $this->createMock(StateStore::class);
		$states->method('all')->willReturn(array_map(static fn (int $at): ListState => new ListState(attemptAt: $at), $attempts));
		$settings = $this->createMock(AppSettings::class);
		$settings->method('isEnabled')->willReturn(true);
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturn(1792490400);
		return new BlocklistSyncJob($time, $sync ?? $this->createMock(BlocklistSync::class), $sources, $states, $settings);
	}

	private function source(string $id, ?int $interval): BlocklistSource {
		return new BlocklistSource($id, $id, 'https://lists.example.org/' . $id, ListFormat::Cidr, BlocklistSource::PURPOSE_TOR, null, true, $interval, false);
	}
}
