<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\AdminChange;

use OCA\IntrusionDetection\Check\Checks\AdminChange;
use OCA\IntrusionDetection\Check\Checks\AdminChangeDetector;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Db\ConfigSnapshotMapper;
use OCP\AppFramework\Utility\ITimeFactory;

/**
 * Compares the watched security settings with the last snapshot and records
 * one detection per changed setting.
 *
 * - The snapshot holds a keyed hash of each value and, unless the value is
 *   secret, a shortened display value. A row is written only on a change.
 * - The first run only records the baseline and reports nothing. So does a
 *   run after the check was switched off, as nobody can tell when the
 *   changes in between happened.
 * - Changes of this app's settings made through the app (admin page, occ
 *   intrusion:*) are reported at once with the actor, and the snapshot is
 *   updated then; the watch only finds those made around the app.
 */
class ConfigWatch {
	public function __construct(
		private readonly WatchedSettings $watched,
		private readonly ConfigSnapshotMapper $snapshots,
		private readonly Fingerprinter $fingerprinter,
		private readonly AdminChangeDetector $detector,
		private readonly Settings $settings,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * @return int the number of changed settings found
	 */
	public function run(): int {
		if ($this->settings->configuredMode(AdminChange::ID) === Mode::Off) {
			if ($this->settings->getInt(GlobalSettings::CONFIG_WATCH_BASELINE) !== 0) {
				$this->settings->setGlobal(GlobalSettings::CONFIG_WATCH_BASELINE, 0);
			}
			return 0;
		}

		$now = $this->timeFactory->getTime();
		$baseline = $this->settings->getInt(GlobalSettings::CONFIG_WATCH_BASELINE) === 0;
		$current = $this->watched->read();
		$snapshot = $this->snapshots->all();
		$changes = [];

		foreach ($current as $key => $value) {
			$hash = $this->fingerprinter->setting($value->canonical());
			$row = $snapshot[$key] ?? null;
			unset($snapshot[$key]);
			if ($row !== null && hash_equals($row['hash'], $hash)) {
				continue;
			}
			$this->snapshots->store($key, $hash, $value->display(), $now);
			if ($baseline || ($row === null && $value->fixed)) {
				// A setting watched for the first time is recorded silently.
				continue;
			}
			$changes[] = [
				'key' => $key,
				'old' => $row === null ? null : DisplayValue::decode($row['display']),
				'new' => $value->value,
				'secret' => $value->secret || ($row !== null && $row['display'] === null),
			];
		}

		// Settings that were set at the last run and are gone now. When a
		// source could not be read, nothing is taken as removed.
		if ($this->watched->lastReadComplete()) {
			$unset = $this->fingerprinter->setting(WatchedValue::canonicalOf(null));
			foreach ($snapshot as $key => $row) {
				if (hash_equals($row['hash'], $unset)) {
					continue;
				}
				$secret = $row['display'] === null;
				$this->snapshots->store($key, $unset, $secret ? null : DisplayValue::encode(null), $now);
				if (!$baseline) {
					$changes[] = ['key' => $key, 'old' => DisplayValue::decode($row['display']), 'new' => null, 'secret' => $secret];
				}
			}
		}

		if ($baseline) {
			$this->settings->setGlobal(GlobalSettings::CONFIG_WATCH_BASELINE, $now);
			return 0;
		}

		foreach ($changes as $change) {
			$name = WatchedSettings::ownName($change['key']);
			$mode = $name !== null && !$change['secret'] && $this->isScalarOrList($change['old'])
				? $this->detector->modeBefore($name, $change['old'])
				: null;
			$this->detector->settingChanged($change['key'], $change['old'], $change['new'], $change['secret'], ActorResolver::UNKNOWN, true, $mode);
		}
		return count($changes);
	}

	/**
	 * One of this app's settings was changed through the app: report it with
	 * the actor and keep the snapshot current, so the watch does not report
	 * it again.
	 *
	 * @param int|float|bool|string|list<string> $old
	 * @param int|float|bool|string|list<string> $new
	 */
	public function ownSettingChanged(string $name, int|float|bool|string|array $old, int|float|bool|string|array $new, string $actor, ModeState $mode): void {
		if ($this->settings->getInt(GlobalSettings::CONFIG_WATCH_BASELINE) !== 0) {
			$value = WatchedSettings::ownValue($name, $new);
			$this->snapshots->store($value->key, $this->fingerprinter->setting($value->canonical()), $value->display(), $this->timeFactory->getTime());
		}
		$this->detector->settingChanged(WatchedSettings::ownKey($name), $old, $new, false, $actor, false, $mode);
	}

	/**
	 * @psalm-assert-if-true int|float|bool|string|list<string> $value
	 */
	private function isScalarOrList(mixed $value): bool {
		return is_scalar($value) || (is_array($value) && array_is_list($value));
	}
}
