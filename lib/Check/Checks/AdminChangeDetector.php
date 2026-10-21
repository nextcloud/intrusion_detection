<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks;

use OCA\IntrusionDetection\AdminChange\ActorResolver;
use OCA\IntrusionDetection\AdminChange\DisplayValue;
use OCA\IntrusionDetection\AdminChange\WatchedSettings;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Check\Severity;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Keys;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Notification\AdminAlerts;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCP\AppFramework\Utility\ITimeFactory;

/**
 * Records one detection of {@see AdminChange} per change, with who made it,
 * the old and the new value, and the severity of the change:
 *
 * - high: administration rights granted (directly or through a delegated
 *   group), the brute-force allowlist or `trusted_proxies` changed, 2FA
 *   enforcement switched off, this app switched off, learning mode started,
 *   a check weakened to Observe or Off, or four-eyes approval switched off;
 * - medium: an app switched on or off, a group administrator appointed, a
 *   running learning period made longer;
 * - low: everything else.
 *
 * Every administrator is notified, also the one who made the change; the
 * bell and the email are aggregated per kind of change and hour.
 */
class AdminChangeDetector {
	public function __construct(
		private readonly ResponseEngine $engine,
		private readonly Settings $settings,
		private readonly ActorResolver $actors,
		private readonly RemoteAddressResolver $addresses,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * @param array<string, mixed> $facts what the change was about (group, app, approval …)
	 * @param string $alertKey changes with the same key share one notification per hour
	 * @param bool $withAddress record the address of the current request as the actor's
	 * @param list<ResponseType>|null $responses run these instead of the configured ones
	 */
	public function record(string $kind, Severity $severity, string $actor, ?string $subject, array $facts, string $alertKey, ?ModeState $mode = null, bool $withAddress = true, ?array $responses = null): ?Detection {
		$facts = ['kind' => $kind, 'actor' => $actor] + $facts;
		if ($subject !== null) {
			$facts['targets'] = [$subject];
		}
		if ($withAddress && !$this->actors->isCommandLine()) {
			$ip = $this->addresses->current()?->ip;
			if ($ip !== null) {
				$facts['actor_ip'] = $ip;
			}
		}
		$facts[AdminAlerts::FACT_ALERT_KEY] = $alertKey;
		$facts[AdminAlerts::FACT_ALL_ADMINS] = true;
		return $this->engine->handle(new DetectionDraft(
			checkId: AdminChange::ID,
			uid: $subject,
			facts: $facts,
			severity: $severity,
		), $responses, $mode);
	}

	/**
	 * A watched setting changed.
	 *
	 * @param mixed $old the display value before (shortened), unused for secrets
	 * @param mixed $new the display value after (shortened), unused for secrets
	 * @param bool $foundByWatch found by the config watch, which cannot know who made it
	 */
	public function settingChanged(string $key, mixed $old, mixed $new, bool $secret, string $actor, bool $foundByWatch, ?ModeState $mode = null): ?Detection {
		$facts = ['setting' => $key, 'secret' => $secret, 'watch' => $foundByWatch];
		if (!$secret) {
			$facts['old'] = DisplayValue::shorten($old);
			$facts['new'] = DisplayValue::shorten($new);
		}
		return $this->record(
			AdminChange::KIND_SETTING_CHANGED,
			self::settingSeverity($key, $secret ? null : $old, $secret ? null : $new, $this->timeFactory->getTime()),
			$actor,
			null,
			$facts,
			self::settingAlertKey($key),
			$mode,
			!$foundByWatch,
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
		if ($key === WatchedSettings::systemKey('trusted_proxies') || $key === WatchedSettings::BRUTEFORCE_ALLOWLIST) {
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

	/**
	 * The mode this check had before one of the app's own settings changed.
	 * A change that switches the app or this check off, or starts learning
	 * mode, is reported as the check stood before, so the change that silences
	 * it is still told. As this check only notifies, learning mode does not
	 * silence it ({@see Settings::actsWhileLearning()}).
	 *
	 * @param int|float|bool|string|list<string> $old
	 */
	public function modeBefore(string $name, int|float|bool|string|array $old): ModeState {
		$configured = $name === Keys::mode(AdminChange::ID)
			? (is_string($old) ? Mode::tryFrom($old) : null) ?? Mode::Protect
			: $this->settings->configuredMode(AdminChange::ID);
		$enabled = $name === GlobalSettings::ENABLED ? $old === true : $this->settings->isEnabled();
		$learning = $name === GlobalSettings::LEARNING_UNTIL
			? is_int($old) && $old > $this->timeFactory->getTime()
			: $this->settings->isLearning();
		if (!$enabled) {
			return new ModeState($configured, Mode::Off, ModeState::REASON_DISABLED);
		}
		if ($configured === Mode::Protect && $learning && !$this->settings->actsWhileLearning(AdminChange::ID)) {
			return new ModeState($configured, Mode::Observe, ModeState::REASON_LEARNING);
		}
		return new ModeState($configured, $configured);
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
