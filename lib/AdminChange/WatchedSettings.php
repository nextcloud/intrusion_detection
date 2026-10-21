<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\AdminChange;

use OC\SystemConfig;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Keys;
use OCA\IntrusionDetection\Config\Settings;
use OCP\IAppConfig;
use OCP\IL10N;
use Psr\Log\LoggerInterface;

/**
 * The security settings the config watch compares every five minutes, read
 * in one go:
 *
 * - config.php: proxies and forwarded headers, trusted domains, the
 *   overwrite* settings, brute-force protection, debug and log level, 2FA
 *   enforcement, the admin address ranges, and this app's own entries;
 * - app config: the brute-force allowlist, sharing by link, the password
 *   policy, and this app's settings (effective values, internal state left out).
 *
 * Keys are "system:<config.php key>" and "app:<app id>:<key>". A value is
 * secret when Nextcloud masks it: config.php values that the filtered read
 * hides, and app config values marked as sensitive.
 */
class WatchedSettings {
	public const SYSTEM_KEYS = [
		'trusted_proxies', 'forwarded_for_headers', 'trusted_domains',
		'overwritehost', 'overwriteprotocol', 'overwritewebroot', 'overwritecondaddr', 'overwrite.cli.url',
		'auth.bruteforce.protection.enabled', 'debug', 'loglevel',
		'twofactor_enforced', 'twofactor_enforced_groups', 'twofactor_enforced_excluded_groups',
		'allowed_admin_ranges',
	];
	/** Further config.php keys with these prefixes are watched as well */
	public const SYSTEM_PREFIXES = ['overwrite', 'twofactor_enforced', 'intrusion_detection.'];
	public const CORE_KEYS = ['shareapi_allow_links', 'shareapi_enforce_links_password'];
	public const PASSWORD_POLICY_APP = 'password_policy';
	public const BRUTEFORCE_APP = 'bruteForce';
	public const BRUTEFORCE_PREFIX = 'whitelist_';
	/** All allowlist entries together, as one setting */
	public const BRUTEFORCE_ALLOWLIST = 'app:bruteForce:whitelist';
	/** Keys core keeps for every app; app enabling is reported by its own event */
	private const APP_STATE_KEYS = ['enabled', 'installed_version', 'types'];

	private bool $complete = true;

	public function __construct(
		private readonly SystemConfig $systemConfig,
		private readonly IAppConfig $appConfig,
		private readonly Settings $settings,
		private readonly CheckRegistry $registry,
		private readonly GlobalSettings $globals,
		private readonly LoggerInterface $logger,
	) {
	}

	public static function systemKey(string $name): string {
		return 'system:' . $name;
	}

	public static function appKey(string $app, string $key): string {
		return 'app:' . $app . ':' . $key;
	}

	public static function ownKey(string $name): string {
		return self::appKey(Application::APP_ID, $name);
	}

	/**
	 * The name of one of this app's settings, from its watched key.
	 */
	public static function ownName(string $key): ?string {
		$prefix = self::ownKey('');
		return str_starts_with($key, $prefix) ? substr($key, strlen($prefix)) : null;
	}

	/**
	 * @return array<string, WatchedValue> keyed by watched key
	 */
	public function read(): array {
		$this->complete = true;
		$values = [];
		foreach ([$this->system(...), $this->core(...), $this->bruteForce(...), $this->passwordPolicy(...), $this->ownSettings(...)] as $reader) {
			try {
				foreach ($reader() as $value) {
					$values[$value->key] = $value;
				}
			} catch (\Throwable $e) {
				// One unreadable source must not hide changes in the others.
				$this->logger->error('Intrusion detection could not read some watched settings', ['exception' => $e]);
				$this->complete = false;
			}
		}
		return $values;
	}

	/**
	 * Whether the last read() could read every source.
	 */
	public function lastReadComplete(): bool {
		return $this->complete;
	}

	/**
	 * One of this app's settings, as read() has it: compared by the value
	 * stored in the app config (null when unset), so that a default changed
	 * by an update is no change, and shown with its effective value.
	 *
	 * @param int|float|bool|string|list<string> $value the effective value
	 */
	public static function ownValue(string $name, int|float|bool|string|array $value, mixed $stored): WatchedValue {
		return new WatchedValue(self::ownKey($name), $value, false, true, WatchedValue::canonicalOf($stored));
	}

	/**
	 * The current value of one of this app's settings, right after the app changed it.
	 *
	 * @param int|float|bool|string|list<string> $value the effective value
	 */
	public function ownCurrent(string $name, int|float|bool|string|array $value): WatchedValue {
		return self::ownValue($name, $value, $this->appConfig->getAllValues(Application::APP_ID, $name)[$name] ?? null);
	}

	/**
	 * A readable name for a watched setting.
	 */
	public function label(string $key, IL10N $l): string {
		if ($key === self::BRUTEFORCE_ALLOWLIST) {
			return $l->t('Brute-force protection allowlist');
		}
		if ($key === self::appKey('core', 'shareapi_allow_links')) {
			return $l->t('Allow sharing by link');
		}
		if ($key === self::appKey('core', 'shareapi_enforce_links_password')) {
			return $l->t('Enforce passwords for shared links');
		}
		if (str_starts_with($key, 'system:')) {
			return $l->t('%s in config.php', [substr($key, 7)]);
		}
		$own = self::ownName($key);
		if ($own !== null) {
			return $this->ownLabel($own, $l);
		}
		if (str_starts_with($key, self::appKey(self::PASSWORD_POLICY_APP, ''))) {
			return $l->t('Password policy: %s', [substr($key, strlen(self::appKey(self::PASSWORD_POLICY_APP, '')))]);
		}
		$parts = explode(':', $key, 3);
		return count($parts) === 3 ? $l->t('Setting %1$s of the app %2$s', [$parts[2], $parts[1]]) : $key;
	}

	private function ownLabel(string $name, IL10N $l): string {
		foreach ($this->registry->all() as $check) {
			$checkName = $check->texts($l)->name;
			if ($name === Keys::mode($check->id)) {
				return $l->t('Intrusion detection: mode of "%s"', [$checkName]);
			}
			if ($name === Keys::responses($check->id)) {
				return $l->t('Intrusion detection: responses of "%s"', [$checkName]);
			}
			foreach ($check->params as $param) {
				if ($name === Keys::param($check->id, $param->name)) {
					return $l->t('Intrusion detection: "%1$s", setting %2$s', [$checkName, $param->name]);
				}
			}
		}
		return $l->t('Intrusion detection: %s', [$name]);
	}

	/**
	 * @return list<WatchedValue>
	 */
	private function system(): array {
		$keys = array_fill_keys(self::SYSTEM_KEYS, true);
		foreach ($this->systemConfig->getKeys() as $key) {
			if (!is_string($key) || isset($keys[$key])) {
				continue;
			}
			foreach (self::SYSTEM_PREFIXES as $prefix) {
				if (str_starts_with($key, $prefix)) {
					$keys[$key] = false;
					break;
				}
			}
		}
		$values = [];
		foreach ($keys as $key => $fixed) {
			$value = $this->systemConfig->getValue($key, null);
			$filtered = $this->systemConfig->getFilteredValue($key, null);
			$values[] = new WatchedValue(self::systemKey($key), $value, WatchedValue::canonicalOf($filtered) !== WatchedValue::canonicalOf($value), $fixed);
		}
		return $values;
	}

	/**
	 * @return list<WatchedValue>
	 */
	private function core(): array {
		$current = $this->appConfig->getAllValues('core', 'shareapi_');
		$values = [];
		foreach (self::CORE_KEYS as $key) {
			$values[] = new WatchedValue(self::appKey('core', $key), $current[$key] ?? null, $this->isSensitive('core', $key, $current), true);
		}
		return $values;
	}

	/**
	 * @return list<WatchedValue>
	 */
	private function bruteForce(): array {
		$current = $this->appConfig->getAllValues(self::BRUTEFORCE_APP, self::BRUTEFORCE_PREFIX);
		$ranges = [];
		$secret = false;
		foreach ($current as $key => $value) {
			$ranges[] = is_scalar($value) ? (string)$value : '';
			$secret = $secret || $this->isSensitive(self::BRUTEFORCE_APP, (string)$key, $current);
		}
		sort($ranges);
		return [new WatchedValue(self::BRUTEFORCE_ALLOWLIST, $ranges, $secret, true)];
	}

	/**
	 * @return list<WatchedValue>
	 */
	private function passwordPolicy(): array {
		$current = $this->appConfig->getAllValues(self::PASSWORD_POLICY_APP);
		$values = [];
		foreach ($current as $key => $value) {
			$key = (string)$key;
			if (in_array($key, self::APP_STATE_KEYS, true)) {
				continue;
			}
			$values[] = new WatchedValue(self::appKey(self::PASSWORD_POLICY_APP, $key), $value, $this->isSensitive(self::PASSWORD_POLICY_APP, $key, $current), false);
		}
		return $values;
	}

	/**
	 * Every setting this app defines (internal state left out), see {@see self::ownValue()}.
	 *
	 * @return list<WatchedValue>
	 */
	private function ownSettings(): array {
		$stored = $this->appConfig->getAllValues(Application::APP_ID);
		$values = [];
		foreach ($this->globals->all() as $name => $definition) {
			if (!GlobalSettings::isInternal($name)) {
				$values[] = self::ownValue($name, $this->settings->global($name), $stored[$name] ?? null);
			}
		}
		foreach ($this->registry->all() as $check) {
			$values[] = self::ownValue(Keys::mode($check->id), $this->settings->configuredMode($check->id)->value, $stored[Keys::mode($check->id)] ?? null);
			$values[] = self::ownValue(Keys::responses($check->id), array_map(static fn (ResponseType $r): string => $r->value, $this->settings->responses($check->id)), $stored[Keys::responses($check->id)] ?? null);
			foreach ($this->settings->params($check->id) as $name => $value) {
				$values[] = self::ownValue(Keys::param($check->id, $name), $value, $stored[Keys::param($check->id, $name)] ?? null);
			}
		}
		return $values;
	}

	/**
	 * @param array<string, mixed> $current the app's values, to tell a missing key from an unknown one
	 */
	private function isSensitive(string $app, string $key, array $current): bool {
		if (!array_key_exists($key, $current)) {
			return false;
		}
		try {
			return $this->appConfig->isSensitive($app, $key, null);
		} catch (\Throwable) {
			// When in doubt, treat the value as secret.
			return true;
		}
	}
}
