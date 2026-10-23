<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Check\Checks\TokenConcurrentUse;

use OC\Memcache\ArrayCache;
use OCA\IntrusionDetection\Cache\KeyLock;
use OCA\IntrusionDetection\Check\Checks\TokenConcurrentUse\CredentialTracker;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Tests\Unit\Cache\FixedCaches;
use Test\TestCase;

class CredentialTrackerTest extends TestCase {
	public function testAUseFromAnotherNetworkAtTheSameTimeIsNotOverwritten(): void {
		$cache = new class('ids-test') extends ArrayCache {
			/** @var ?\Closure(): void runs once after the next read, as a request on another web server would */
			public ?\Closure $afterGet = null;

			public function get($key) {
				$value = parent::get($key);
				$after = $this->afterGet;
				$this->afterGet = null;
				if ($after !== null) {
					$after();
				}
				return $value;
			}
		};
		$caches = new FixedCaches($cache, $cache);
		$settings = $this->createMock(CheckSettings::class);
		$settings->method('paramInt')->willReturnCallback(static fn (string $check, string $name): int => $name === 'window' ? 600 : 3);
		$tracker = new CredentialTracker($caches, $settings, new KeyLock($caches));
		$now = 1_800_000_000;

		$cache->afterGet = static function () use ($tracker, $now): void {
			$tracker->track('cred', SourceKey::fromIp('203.0.113.9'), 'tag', $now);
		};
		$tracker->track('cred', SourceKey::fromIp('198.51.100.7'), 'tag', $now);

		$stored = $cache->get(CredentialTracker::KEY_PREFIX . 'cred');
		$this->assertIsArray($stored);
		$networks = array_map(static fn (array $visit): string => $visit[0], $stored['v']);
		$this->assertEqualsCanonicalizing([SourceKey::fromIp('203.0.113.9')->netKey, SourceKey::fromIp('198.51.100.7')->netKey], $networks, 'both uses are in the history');
	}
}
