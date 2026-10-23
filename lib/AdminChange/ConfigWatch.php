<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\AdminChange;

use OCA\IntrusionDetection\AdminChange\Db\ConfigSnapshotMapper;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\AdminChange\AdminChange;
use OCA\IntrusionDetection\Check\Checks\AdminChange\AdminChangeDetector;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Keys;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Signal\SignalDispatcher;
use OCA\IntrusionDetection\State\AppState;
use OCP\App\IAppManager;
use OCP\AppFramework\Utility\ITimeFactory;

/**
 * Compares the watched security settings with the last snapshot and records
 * one detection per changed setting.
 *
 * - The snapshot holds a keyed hash of each value and, unless the value is
 *   secret, a shortened display value. A row is written only on a change.
 * - The first run only records the baseline and reports nothing.
 * - The watch never goes silent. While the check does not run (switched
 *   off, or the master switch off), it only reports the change that
 *   silenced it, judged by the mode before, and keeps the rest of the
 *   snapshot as it was. Once the check runs again, everything that changed
 *   in between is compared with that snapshot and reported.
 * - Changes of this app's settings made through the app (admin page, occ
 *   intrusion:*) are reported at once with the actor, and the snapshot is
 *   updated then; the watch only finds those made around the app. Changes
 *   the app makes on its own (the learning period) only update the snapshot.
 * - The hashes are keyed with the instance `secret`. The snapshot row
 *   META_KEY holds a hash of a fixed text under that key: when it no longer
 *   matches, the secret changed. Then that change is reported once, every
 *   setting is recorded again without reporting it (all hashes differ, not
 *   the values), and SECRET_CHANGED_STATE holds the time, so that the
 *   decoys created before can be told apart.
 * - This app's settings are compared by their stored values. Settings an
 *   update removed are dropped from the snapshot silently, and after an
 *   update of this app its settings are recorded again silently (an update
 *   may rename settings or change defaults; the snapshot row META_VERSION
 *   holds the version of the last run).
 */
class ConfigWatch {
	/** When the watched settings were first recorded; 0 until then */
	public const BASELINE_STATE = 'config_watch_baseline';
	/** Snapshot row that holds the app version of the last run */
	public const META_VERSION = 'meta:app_version';
	/** Snapshot row that holds the hash of a fixed text under the current key */
	public const META_KEY = 'meta:key_id';
	/** When the watch found that the instance secret changed; 0 when it never did */
	public const SECRET_CHANGED_STATE = 'secret_changed_at';
	/** The setting reported when the instance secret changed */
	public const SECRET_KEY = 'system:secret';

	public function __construct(
		private readonly WatchedSettings $watched,
		private readonly ConfigSnapshotMapper $snapshots,
		private readonly Fingerprinter $fingerprinter,
		private readonly SignalDispatcher $dispatcher,
		private readonly CheckSettings $settings,
		private readonly ITimeFactory $timeFactory,
		private readonly IAppManager $appManager,
		private readonly AppState $state,
	) {
	}

	/**
	 * @return int the number of changed settings found
	 */
	public function run(): int {
		$now = $this->timeFactory->getTime();
		$baseline = $this->state->getInt(self::BASELINE_STATE) === 0;
		$silenced = $this->isSilenced();
		if ($silenced && $baseline) {
			return 0;
		}
		$current = $this->watched->read();
		$snapshot = $this->snapshots->all();
		$version = $this->appManager->getAppVersion(Application::APP_ID);
		$versionHash = $this->fingerprinter->setting(WatchedValue::canonicalOf($version));
		$updated = !isset($snapshot[self::META_VERSION]) || !hash_equals($snapshot[self::META_VERSION]['hash'], $versionHash);
		$keyId = $this->fingerprinter->setting(self::META_KEY);
		$rekeyed = !$baseline && isset($snapshot[self::META_KEY]) && !hash_equals($snapshot[self::META_KEY]['hash'], $keyId);
		if (!isset($snapshot[self::META_KEY]) || $rekeyed) {
			$this->snapshots->store(self::META_KEY, $keyId, null, $now);
		}
		unset($snapshot[self::META_VERSION], $snapshot[self::META_KEY]);
		if ($rekeyed) {
			// Every keyed hash differs now, whatever changed: record them all again.
			$baseline = true;
			$silenced = false;
		}
		$changes = [];

		foreach ($current as $key => $value) {
			$hash = $this->fingerprinter->setting($value->canonical());
			$row = $snapshot[$key] ?? null;
			unset($snapshot[$key]);
			if ($row !== null && hash_equals($row['hash'], $hash)) {
				continue;
			}
			if ($silenced && !self::isSilencing($key)) {
				// Compared once the check runs again.
				continue;
			}
			$this->snapshots->store($key, $hash, $value->display(), $now);
			if ($baseline || ($row === null && $value->fixed)) {
				// A setting watched for the first time is recorded silently.
				continue;
			}
			$own = WatchedSettings::ownName($key) !== null;
			if (!$silenced && $own && $row !== null && ($updated || $row['display'] === $value->display())) {
				// Recorded again after an update of the app, or stored differently with the same effect.
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
		if (!$silenced && $this->watched->lastReadComplete()) {
			$unset = $this->fingerprinter->setting(WatchedValue::canonicalOf(null));
			foreach ($snapshot as $key => $row) {
				if (hash_equals($row['hash'], $unset)) {
					continue;
				}
				$secret = $row['display'] === null;
				if (WatchedSettings::ownName($key) !== null) {
					// Every setting the app defines is read, so this one is no longer defined.
					$this->snapshots->delete($key);
					continue;
				}
				$this->snapshots->store($key, $unset, $secret ? null : DisplayValue::encode(null), $now);
				if (!$baseline) {
					$changes[] = ['key' => $key, 'old' => DisplayValue::decode($row['display']), 'new' => null, 'secret' => $secret];
				}
			}
		}

		if ($updated && !$silenced) {
			$this->snapshots->store(self::META_VERSION, $versionHash, DisplayValue::encode($version), $now);
		}
		if ($rekeyed) {
			$this->state->setInt(self::BASELINE_STATE, $now);
			$this->state->setInt(self::SECRET_CHANGED_STATE, $now);
			$this->dispatcher->dispatch(AdminChangeDetector::settingChange(self::SECRET_KEY, null, null, true, ActorResolver::UNKNOWN, true, $now));
			return 1;
		}
		if ($baseline) {
			$this->state->setInt(self::BASELINE_STATE, $now);
			return 0;
		}

		// The settings that silence the check are judged together by the mode before all of them changed.
		$silencing = [];
		foreach ($changes as $change) {
			$name = WatchedSettings::ownName($change['key']);
			if ($name !== null && in_array($name, self::silencing(), true) && !$change['secret'] && $this->isScalarOrList($change['old'])) {
				$silencing[$name] = $change['old'];
			}
		}
		foreach ($changes as $change) {
			$name = WatchedSettings::ownName($change['key']);
			$mode = $name !== null && !$change['secret'] && $this->isScalarOrList($change['old'])
				? $this->settings->modeStateBeforeAll(AdminChange::ID, isset($silencing[$name]) ? $silencing : [$name => $change['old']], $now)
				: null;
			$this->dispatcher->dispatch(AdminChangeDetector::settingChange($change['key'], $change['old'], $change['new'], $change['secret'], ActorResolver::UNKNOWN, true, $now), $mode);
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
	public function ownSettingChanged(string $name, int|float|bool|string|array $old, int|float|bool|string|array $new, string $actor): void {
		$this->record($name, $new, false);
		$now = $this->timeFactory->getTime();
		$this->dispatcher->dispatch(
			AdminChangeDetector::settingChange(WatchedSettings::ownKey($name), $old, $new, false, $actor, false, $now),
			$this->settings->modeStateBefore(AdminChange::ID, $name, $old, $now),
		);
	}

	/**
	 * One of this app's settings was changed by the app itself, which is no
	 * administration change: only keep the snapshot current, so the watch
	 * does not report it either.
	 *
	 * @param int|float|bool|string|list<string> $new
	 */
	public function ownSettingRecorded(string $name, int|float|bool|string|array $new): void {
		$this->record($name, $new, true);
	}

	/**
	 * @param int|float|bool|string|list<string> $new
	 * @param bool $always also while the check is silenced; else only a setting that silences it is recorded then
	 */
	private function record(string $name, int|float|bool|string|array $new, bool $always): void {
		if ($this->state->getInt(self::BASELINE_STATE) === 0) {
			return;
		}
		if (!$always && !in_array($name, self::silencing(), true) && $this->isSilenced()) {
			return;
		}
		$value = $this->watched->ownCurrent($name, $new);
		$this->snapshots->store($value->key, $this->fingerprinter->setting($value->canonical()), $value->display(), $this->timeFactory->getTime());
	}

	/**
	 * Whether the check does not run now, so that nothing it found would be recorded.
	 */
	private function isSilenced(): bool {
		return !$this->settings->modeState(AdminChange::ID)->runs();
	}

	/**
	 * The settings that silence the check when switched off.
	 *
	 * @return list<string>
	 */
	private static function silencing(): array {
		return [GlobalSettings::ENABLED, Keys::mode(AdminChange::ID)];
	}

	private static function isSilencing(string $key): bool {
		$name = WatchedSettings::ownName($key);
		return $name !== null && in_array($name, self::silencing(), true);
	}

	/**
	 * @psalm-assert-if-true int|float|bool|string|list<string> $value
	 */
	private function isScalarOrList(mixed $value): bool {
		return is_scalar($value) || (is_array($value) && array_is_list($value));
	}
}
