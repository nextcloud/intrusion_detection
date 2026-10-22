<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\BackgroundJob;

use OCA\IntrusionDetection\Blocklist\BlocklistSync;
use OCA\IntrusionDetection\Blocklist\SourceRepository;
use OCA\IntrusionDetection\Blocklist\StateStore;
use OCA\IntrusionDetection\Config\AppSettings;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\BackgroundJob\TimedJob;

/**
 * Downloads the enabled lists that are due.
 *
 * Runs every {@see BlocklistSync::INTERVAL}, or as often as the shortest interval
 * of an enabled list (the Tor exit list: hourly), and every 15 minutes while
 * an enabled list has never been downloaded. With no list enabled it only
 * removes what disabled lists left behind.
 */
class BlocklistSyncJob extends TimedJob {
	public const MIN_INTERVAL = 900;

	public function __construct(
		ITimeFactory $time,
		private readonly BlocklistSync $sync,
		private readonly SourceRepository $sources,
		private readonly StateStore $states,
		private readonly AppSettings $settings,
	) {
		parent::__construct($time);
		$this->setInterval($this->interval());
	}

	#[\Override]
	protected function run(mixed $argument): void {
		if (!$this->settings->isEnabled() || !$this->sync->hasActiveSources()) {
			$this->sync->cleanup();
			return;
		}
		$this->sync->syncDue();
	}

	private function interval(): int {
		$interval = BlocklistSync::INTERVAL;
		$states = $this->states->all();
		foreach ($this->sources->enabled() as $source) {
			if (($states[$source->id] ?? null)?->attemptAt === null) {
				return self::MIN_INTERVAL;
			}
			$interval = min($interval, $source->effectiveInterval());
		}
		return max(self::MIN_INTERVAL, $interval);
	}
}
