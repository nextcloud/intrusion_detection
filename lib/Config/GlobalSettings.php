<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Config;

use OCA\IntrusionDetection\Definition\InvalidParamException;
use OCA\IntrusionDetection\Definition\ParamDefinition;
use OCA\IntrusionDetection\Definition\ParamPreset;
use OCA\IntrusionDetection\Definition\ParamType;

/**
 * The settings that belong to the app rather than to one check.
 *
 * Each one is a {@see ParamDefinition}, so global settings are validated
 * exactly like check parameters, and the config lexicon is generated from
 * these definitions and the check registry together. The key is the
 * definition's name.
 */
final class GlobalSettings {
	/** Not 'enabled': core keeps every app's enabled state under that key */
	public const ENABLED = 'protection_enabled';
	public const LEARNING_UNTIL = 'learning_until';
	public const BAN_DURATION_1 = 'ban_duration_1';
	public const BAN_DURATION_2 = 'ban_duration_2';
	public const BAN_DURATION_3 = 'ban_duration_3';
	public const BAN_HISTORY_DAYS = 'ban_history_days';
	public const BAN_NET_AFTER = 'ban_net_after';
	public const BAN_SHARED_IP_USERS = 'ban_shared_ip_users';
	/** Days detections, the login history and the security change log are kept */
	public const RETENTION_DETECTIONS_DAYS = 'retention_detections_days';

	public const EXPORT_FORMATS = 'export_formats';
	public const BLOCKLIST_SOURCES = 'blocklist_sources';
	/** The groups whose members get the admin notifications */
	public const NOTIFY_ADMIN_GROUP = 'notify_admin_group';
	/** Detections of at least this severity are also emailed to them ("never" for no emails) */
	public const NOTIFY_ADMIN_EMAIL_MIN_SEVERITY = 'notify_admin_email_min_severity';
	/** A second administrator must approve every new administrator */
	public const ADMIN_CHANGE_REQUIRE_APPROVAL = 'admin_change_require_approval';

	/** How often the administrators get the digest email: off, daily or weekly */
	public const DIGEST_FREQUENCY = 'digest_frequency';
	/** Whether the typed events for webhooks carry the address */
	public const EVENTS_INCLUDE_IP = 'events_include_ip';

	/** The step-up policies for which a remembered device confirms a login */
	public const STEP_UP_KNOWN_DEVICE_OK_FOR = 'step_up_known_device_ok_for';
	/** Whether an administrator can approve a login that nothing else can confirm */
	public const STEP_UP_ADMIN_APPROVAL = 'step_up_admin_approval';
	/** Whether users may remember a browser after confirming a login */
	public const KNOWN_DEVICE_ENABLED = 'known_device_enabled';

	/** Whether the address risk score lowers limits and asks for confirmation (concept section 10.18) */
	public const RISK_ENABLED = 'risk_enabled';
	/** The trusted networks: the company's own networks and VPN, whose addresses are never risky */
	public const RISKY_NETWORK_OFFICE_NETWORKS = 'risky_network_office_networks';
	/** Whether a password login of an administrator from outside the trusted networks needs extra confirmation */
	public const ADMIN_TRUSTED_NETWORKS_ONLY = 'admin_trusted_networks_only';
	/** Groups whose members may log in from hosting and Tor networks without extra confirmation */
	public const RISKY_NETWORK_EXEMPT_GROUPS = 'risky_network_exempt_groups';
	/** Whether users see the intrusion detection part of their security settings */
	public const PERSONAL_PAGE_ENABLED = 'personal_page_enabled';
	/** Days without use after which the daily job removes app passwords and remembered browsers; 0 keeps them */
	public const STALE_CREDENTIALS_REMOVE_DAYS = 'stale_credentials_remove_days';
	/** The removal takes at least this many days without use */
	public const STALE_CREDENTIALS_MIN_REMOVE_DAYS = 90;

	/**
	 * What happens by default to a login that needs extra confirmation when
	 * nothing can confirm it, by step-up policy
	 * ({@see \OCA\IntrusionDetection\Confirm\StepUpPolicy}); each has
	 * the setting {@see self::stepUpNoMethod()}.
	 */
	public const STEP_UP_NO_METHOD_DEFAULTS = [
		'flagged_source' => 'refuse',
		'sprayed_password' => 'refuse',
		'protected_account' => 'allow_notify',
		'breached_password' => 'allow_force_change',
		'risky_network' => 'allow_notify',
		'risk_high' => 'refuse',
		'admin_outside_networks' => 'refuse',
	];
	/** The choices of those settings ({@see \OCA\IntrusionDetection\Confirm\NoMethodOutcome}) */
	public const NO_METHOD_OUTCOMES = ['refuse', 'allow_notify', 'allow_force_change'];
	/** The policies for which a remembered device confirms a login by default */
	public const STEP_UP_KNOWN_DEVICE_DEFAULT = ['flagged_source', 'protected_account', 'risky_network', 'risk_high'];
	/** The policies that setting may name: every one but a sprayed or breached password and an administrator outside the trusted networks */
	public const STEP_UP_KNOWN_DEVICE_PATTERN = '/^(flagged_source|protected_account|risky_network|risk_high)$/';

	/** Seconds in the learning period that starts when the app is first enabled */
	public const LEARNING_DEFAULT_PERIOD = 7 * 86400;

	/** @var array<string, ParamDefinition>|null */
	private ?array $definitions = null;

	/**
	 * @return array<string, ParamDefinition> keyed by setting name
	 */
	public function all(): array {
		if ($this->definitions === null) {
			$list = [
				new ParamDefinition(self::ENABLED, ParamType::Bool, true),
				new ParamDefinition(self::LEARNING_UNTIL, ParamType::Int, 0, min: 0),
				// The three escalation levels: first block, repeat within the history window, and after that.
				new ParamDefinition(self::BAN_DURATION_1, ParamType::Duration, 14400, min: 300, max: 90 * 86400, preset: ParamPreset::BlockDuration),
				new ParamDefinition(self::BAN_DURATION_2, ParamType::Duration, 86400, min: 300, max: 90 * 86400, preset: ParamPreset::BlockDuration),
				new ParamDefinition(self::BAN_DURATION_3, ParamType::Duration, 604800, min: 300, max: 90 * 86400, preset: ParamPreset::BlockDuration),
				new ParamDefinition(self::BAN_HISTORY_DAYS, ParamType::Int, 30, min: 1, max: 365),
				new ParamDefinition(self::BAN_NET_AFTER, ParamType::Int, 3, min: 2, max: 256),
				new ParamDefinition(self::BAN_SHARED_IP_USERS, ParamType::Int, 5, min: 0, max: 10000),
				new ParamDefinition(self::RETENTION_DETECTIONS_DAYS, ParamType::Int, 90, min: 7, max: 730),
				new ParamDefinition(self::EXPORT_FORMATS, ParamType::StringList, [], itemPattern: '/^(txt|nft|ipset|log)$/', maxItems: 4),
				new ParamDefinition(self::BLOCKLIST_SOURCES, ParamType::Json, '[]'),
				new ParamDefinition(self::NOTIFY_ADMIN_GROUP, ParamType::StringList, ['admin'], itemPattern: '/^[^\x00-\x1f\x7f]{1,255}$/u', maxItems: 10),
				new ParamDefinition(self::NOTIFY_ADMIN_EMAIL_MIN_SEVERITY, ParamType::Choice, 'high', choices: ['low', 'medium', 'high', 'critical', 'never']),
				new ParamDefinition(self::ADMIN_CHANGE_REQUIRE_APPROVAL, ParamType::Bool, false),
				new ParamDefinition(self::DIGEST_FREQUENCY, ParamType::Choice, 'weekly', choices: ['off', 'daily', 'weekly']),
				new ParamDefinition(self::EVENTS_INCLUDE_IP, ParamType::Bool, true),
				...array_map(
					static fn (string $policy, string $outcome): ParamDefinition => new ParamDefinition(self::stepUpNoMethod($policy), ParamType::Choice, $outcome, choices: self::NO_METHOD_OUTCOMES),
					array_keys(self::STEP_UP_NO_METHOD_DEFAULTS),
					self::STEP_UP_NO_METHOD_DEFAULTS,
				),
				new ParamDefinition(self::STEP_UP_KNOWN_DEVICE_OK_FOR, ParamType::StringList, self::STEP_UP_KNOWN_DEVICE_DEFAULT, itemPattern: self::STEP_UP_KNOWN_DEVICE_PATTERN, maxItems: count(self::STEP_UP_NO_METHOD_DEFAULTS)),
				new ParamDefinition(self::STEP_UP_ADMIN_APPROVAL, ParamType::Bool, false),
				new ParamDefinition(self::KNOWN_DEVICE_ENABLED, ParamType::Bool, true),
				new ParamDefinition(self::RISK_ENABLED, ParamType::Bool, true),
				new ParamDefinition(self::RISKY_NETWORK_OFFICE_NETWORKS, ParamType::CidrList, [], maxItems: 100),
				new ParamDefinition(self::ADMIN_TRUSTED_NETWORKS_ONLY, ParamType::Bool, false),
				new ParamDefinition(self::RISKY_NETWORK_EXEMPT_GROUPS, ParamType::StringList, [], itemPattern: '/^[^\x00-\x1f\x7f]{1,255}$/u', maxItems: 20),
				new ParamDefinition(self::PERSONAL_PAGE_ENABLED, ParamType::Bool, true),
				new ParamDefinition(self::STALE_CREDENTIALS_REMOVE_DAYS, ParamType::Int, 0, min: 0, max: 3650),
			];
			$this->definitions = [];
			foreach ($list as $definition) {
				$this->definitions[$definition->name] = $definition;
			}
		}
		return $this->definitions;
	}

	public function get(string $name): ?ParamDefinition {
		return $this->all()[$name] ?? null;
	}

	/**
	 * The setting that holds what happens to a login of a step-up policy
	 * that nothing can confirm.
	 */
	public static function stepUpNoMethod(string $policy): string {
		return 'step_up_no_method_' . $policy;
	}

	/**
	 * A rule a value must pass besides its definition's type and range.
	 *
	 * @param int|float|bool|string|list<string> $value valid for its definition
	 * @throws InvalidParamException
	 */
	public static function checkRule(string $name, int|float|bool|string|array $value): void {
		if ($name === self::STALE_CREDENTIALS_REMOVE_DAYS && $value !== 0 && $value < self::STALE_CREDENTIALS_MIN_REMOVE_DAYS) {
			throw new InvalidParamException('zero_or_at_least', ['param' => $name, 'min' => self::STALE_CREDENTIALS_MIN_REMOVE_DAYS]);
		}
	}
}
