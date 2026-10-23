<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\AdminChange;

use OCA\IntrusionDetection\AdminChange\ActorResolver;
use OCA\IntrusionDetection\AdminChange\DisplayValue;
use OCA\IntrusionDetection\AdminChange\WatchedSettings;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\Severity;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Signal\AdminChanged;
use OCA\IntrusionDetection\Signal\IDetector;
use OCA\IntrusionDetection\Signal\ISignal;

/**
 * Records one detection of {@see AdminChange} per change, with who made it,
 * the old and the new value, and the severity of the change:
 *
 * - high: administration rights granted (directly or through a delegated
 *   group), the brute-force allowlist or `trusted_proxies` changed, 2FA
 *   enforcement switched off, the instance secret changed, this app switched off, learning mode started,
 *   a check weakened to Observe or Off, or four-eyes approval switched off;
 * - medium: an app switched on or off, a group administrator appointed, a
 *   running learning period made longer;
 * - low: everything else.
 *
 * Every administrator is notified, also the one who made the change; the
 * bell and the email are aggregated per kind of change and hour.
 *
 * @template-implements IDetector<AdminChanged>
 */
class AdminChangeDetector implements IDetector {
	public function __construct(
		private readonly ActorResolver $actors,
		private readonly RemoteAddressResolver $addresses,
	) {
	}

	/**
	 * One detection per change, in the mode the dispatcher hands over: a
	 * change of this app's settings is judged by the mode before it.
	 *
	 * @param AdminChanged $signal
	 * @return list<DetectionDraft>
	 */
	#[\Override]
	public function detect(#[\SensitiveParameter] ISignal $signal, ModeState $mode): iterable {
		$ip = $signal->withAddress && !$this->actors->isCommandLine() ? $this->addresses->current()?->ip : null;
		return [new DetectionDraft(
			checkId: AdminChange::ID,
			uid: $signal->subject,
			facts: AdminChangeFacts::fromArray($signal->facts)->of($signal->kind, $signal->actor, $signal->subject, $ip, $signal->alertKey),
			severity: $signal->severity,
			mode: $mode,
		)];
	}

	/**
	 * A watched setting changed.
	 *
	 * @param mixed $old the display value before (shortened), unused for secrets
	 * @param mixed $new the display value after (shortened), unused for secrets
	 * @param bool $foundByWatch found by the config watch, which cannot know who made it
	 */
	public static function settingChange(string $key, mixed $old, mixed $new, bool $secret, string $actor, bool $foundByWatch, int $now): AdminChanged {
		$facts = new AdminChangeFacts(
			setting: $key,
			secret: $secret,
			watch: $foundByWatch,
			hasValues: !$secret,
			old: $secret ? null : DisplayValue::shorten($old),
			new: $secret ? null : DisplayValue::shorten($new),
		);
		return new AdminChanged(
			AdminChange::KIND_SETTING_CHANGED,
			self::settingSeverity($key, $secret ? null : $old, $secret ? null : $new, $now),
			$actor,
			null,
			facts: $facts->toArray(),
			alertKey: self::settingAlertKey($key),
			withAddress: !$foundByWatch,
		);
	}

	/**
	 * Changes of this app's settings and of the password policy share one
	 * notification per hour, so that saving a whole page of settings is one
	 * notification, not dozens. Every other watched setting has its own.
	 */
	public static function settingAlertKey(string $key): string {
		foreach ([WatchedSettings::ownKey(''), WatchedSettings::appKey(WatchedSettings::PASSWORD_POLICY_APP, '')] as $prefix) {
			if (str_starts_with($key, $prefix)) {
				return 'setting:' . rtrim($prefix, ':');
			}
		}
		return 'setting:' . $key;
	}

	/**
	 * How severe a change of a watched setting is. For secret values only the
	 * key counts, as the values are unknown.
	 */
	public static function settingSeverity(string $key, mixed $old, mixed $new, int $now): Severity {
		if ($key === WatchedSettings::systemKey('trusted_proxies') || $key === WatchedSettings::BRUTEFORCE_ALLOWLIST || $key === WatchedSettings::systemKey('secret')) {
			return Severity::High;
		}
		if ($key === WatchedSettings::systemKey('twofactor_enforced') && self::isOn($old) && !self::isOn($new)) {
			return Severity::High;
		}
		$name = WatchedSettings::ownName($key);
		if ($name === null) {
			return Severity::Low;
		}
		if (($name === GlobalSettings::ENABLED || $name === GlobalSettings::ADMIN_CHANGE_REQUIRE_APPROVAL) && self::isOn($old) && !self::isOn($new)) {
			return Severity::High;
		}
		if ($name === GlobalSettings::LEARNING_UNTIL && is_numeric($new) && (int)$new > $now) {
			$wasLearning = is_numeric($old) && (int)$old > $now;
			if (!$wasLearning) {
				return Severity::High;
			}
			if ((int)$new > (int)$old) {
				return Severity::Medium;
			}
		}
		if (preg_match('/^check_[a-z0-9_]{3,32}_mode$/', $name) === 1 && self::modeRank($new) < self::modeRank($old)) {
			return Severity::High;
		}
		return Severity::Low;
	}

	private static function isOn(mixed $value): bool {
		return $value === true || $value === 1 || (is_string($value) && in_array(strtolower($value), ['1', 'true', 'yes', 'on'], true));
	}

	private static function modeRank(mixed $mode): int {
		return match ($mode) {
			Mode::Off->value => 0,
			Mode::Observe->value => 1,
			Mode::Protect->value => 2,
			default => -1,
		};
	}
}
