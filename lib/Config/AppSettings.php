<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Config;

use OCA\IntrusionDetection\Definition\InvalidParamException;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IAppConfig;
use OCP\IConfig;

/**
 * The settings that belong to the app rather than to one check
 * ({@see GlobalSettings}), read-only and typed. Writes go through
 * {@see \OCA\IntrusionDetection\Configure\SettingsEditor}.
 *
 * With {@see self::LOCK} set in config.php, the settings in
 * {@see GlobalSettings::LOCKED} read as their locked values whatever is
 * stored, so that neither the admin page, the API nor occ can change them.
 */
class AppSettings extends StoredSettings {
	/** The config.php switch that holds the protective settings at their safest values */
	public const LOCK = 'intrusion_detection.locked';

	public function __construct(
		IAppConfig $appConfig,
		private readonly ITimeFactory $timeFactory,
		private readonly IConfig $config,
	) {
		parent::__construct($appConfig);
	}

	/**
	 * A global setting by name, for code that handles all of them alike.
	 *
	 * @return int|float|bool|string|list<string>
	 * @throws InvalidParamException for a name that is no global setting
	 */
	public function value(string $name): int|float|bool|string|array {
		if ($this->isLockedSetting($name)) {
			return GlobalSettings::LOCKED[$name];
		}
		$spec = LexiconData::GLOBALS[$name] ?? throw new InvalidParamException('unknown_param', ['param' => $name]);
		return $this->readSpec($name, $name, $spec);
	}

	/**
	 * Every global setting with its value.
	 *
	 * @return array<string, int|float|bool|string|list<string>>
	 */
	public function all(): array {
		$values = [];
		foreach (array_keys(LexiconData::GLOBALS) as $name) {
			$values[$name] = $this->value($name);
		}
		return $values;
	}

	/**
	 * Whether config.php holds the protective settings at their safest values.
	 */
	public function isLocked(): bool {
		return $this->config->getSystemValueBool(self::LOCK, false);
	}

	/**
	 * Whether the config.php lock holds this global setting now.
	 */
	public function isLockedSetting(string $name): bool {
		return array_key_exists($name, GlobalSettings::LOCKED) && $this->isLocked();
	}

	public function isEnabled(): bool {
		return (bool)$this->value(GlobalSettings::ENABLED);
	}

	/**
	 * Whether users see their security events in their own security settings.
	 */
	public function personalPageEnabled(): bool {
		return $this->isEnabled() && $this->personalPageSwitchedOn();
	}

	/**
	 * The personal page's own switch, whatever the master switch says.
	 */
	public function personalPageSwitchedOn(): bool {
		return (bool)$this->value(GlobalSettings::PERSONAL_PAGE_ENABLED);
	}

	public function learningUntil(): int {
		return (int)$this->value(GlobalSettings::LEARNING_UNTIL);
	}

	public function isLearning(): bool {
		return $this->learningUntil() > $this->timeFactory->getTime();
	}

	/**
	 * Ban durations in seconds for the escalation levels 1, 2 and 3.
	 *
	 * @return array{1: int, 2: int, 3: int}
	 */
	public function banDurations(): array {
		return [
			1 => (int)$this->value(GlobalSettings::BAN_DURATION_1),
			2 => (int)$this->value(GlobalSettings::BAN_DURATION_2),
			3 => (int)$this->value(GlobalSettings::BAN_DURATION_3),
		];
	}

	public function banHistoryDays(): int {
		return (int)$this->value(GlobalSettings::BAN_HISTORY_DAYS);
	}

	public function banNetAfter(): int {
		return (int)$this->value(GlobalSettings::BAN_NET_AFTER);
	}

	public function banSharedIpUsers(): int {
		return (int)$this->value(GlobalSettings::BAN_SHARED_IP_USERS);
	}

	/**
	 * Days detections, the login history and the security change log are kept.
	 */
	public function retentionDays(): int {
		return (int)$this->value(GlobalSettings::RETENTION_DETECTIONS_DAYS);
	}

	/**
	 * @return list<string>
	 */
	public function exportFormats(): array {
		return $this->list(GlobalSettings::EXPORT_FORMATS);
	}

	/**
	 * The configured blocklists, as stored JSON.
	 */
	public function blocklistSources(): string {
		return (string)$this->value(GlobalSettings::BLOCKLIST_SOURCES);
	}

	/**
	 * @return list<string>
	 */
	public function notifyAdminGroups(): array {
		return $this->list(GlobalSettings::NOTIFY_ADMIN_GROUP);
	}

	public function notifyAdminEmailMinSeverity(): string {
		return (string)$this->value(GlobalSettings::NOTIFY_ADMIN_EMAIL_MIN_SEVERITY);
	}

	public function adminChangeRequireApproval(): bool {
		return (bool)$this->value(GlobalSettings::ADMIN_CHANGE_REQUIRE_APPROVAL);
	}

	public function digestFrequency(): string {
		return (string)$this->value(GlobalSettings::DIGEST_FREQUENCY);
	}

	public function eventsIncludeIp(): bool {
		return (bool)$this->value(GlobalSettings::EVENTS_INCLUDE_IP);
	}

	/**
	 * What happens to a login of a step-up policy that nothing can confirm.
	 */
	public function stepUpNoMethod(string $policy): string {
		return (string)$this->value(GlobalSettings::stepUpNoMethod($policy));
	}

	/**
	 * @return list<string>
	 */
	public function stepUpKnownDeviceOkFor(): array {
		return $this->list(GlobalSettings::STEP_UP_KNOWN_DEVICE_OK_FOR);
	}

	public function stepUpAdminApproval(): bool {
		return (bool)$this->value(GlobalSettings::STEP_UP_ADMIN_APPROVAL);
	}

	public function knownDeviceEnabled(): bool {
		return (bool)$this->value(GlobalSettings::KNOWN_DEVICE_ENABLED);
	}

	public function riskEnabled(): bool {
		return (bool)$this->value(GlobalSettings::RISK_ENABLED);
	}

	/**
	 * @return list<string>
	 */
	public function riskyNetworkOfficeNetworks(): array {
		return $this->list(GlobalSettings::RISKY_NETWORK_OFFICE_NETWORKS);
	}

	public function adminTrustedNetworksOnly(): bool {
		return (bool)$this->value(GlobalSettings::ADMIN_TRUSTED_NETWORKS_ONLY);
	}

	/**
	 * @return list<string>
	 */
	public function riskyNetworkExemptGroups(): array {
		return $this->list(GlobalSettings::RISKY_NETWORK_EXEMPT_GROUPS);
	}

	/**
	 * Days without use after which the daily job removes app passwords and remembered browsers; 0 when it does not.
	 */
	public function staleCredentialsRemoveDays(): int {
		return (int)$this->value(GlobalSettings::STALE_CREDENTIALS_REMOVE_DAYS);
	}

	/**
	 * @return list<string>
	 */
	private function list(string $name): array {
		$value = $this->value($name);
		return is_array($value) ? $value : [];
	}
}
