<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Config;

use OCA\IntrusionDetection\Check\Checks\AdminChange;
use OCA\IntrusionDetection\Check\IValidatesParams;
use OCA\IntrusionDetection\Check\ParamDefinition;
use OCA\IntrusionDetection\Check\ParamPreset;
use OCA\IntrusionDetection\Check\ParamType;
use OCA\IntrusionDetection\Confirm\Methods\KnownDeviceMethod;
use OCA\IntrusionDetection\Confirm\NoMethodOutcome;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Confirm\StepUpReasons;
use OCA\IntrusionDetection\Net\ServerAddresses;

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
	public const LEARNING_DECOYS_ACT = 'learning_decoys_act';
	public const LEARNING_NOTICE_SENT = 'learning_notice_sent';
	public const BAN_DURATION_1 = 'ban_duration_1';
	public const BAN_DURATION_2 = 'ban_duration_2';
	public const BAN_DURATION_3 = 'ban_duration_3';
	public const BAN_HISTORY_DAYS = 'ban_history_days';
	public const BAN_NET_AFTER = 'ban_net_after';
	public const BAN_SHARED_IP_USERS = 'ban_shared_ip_users';
	public const RETENTION_DETECTIONS_DAYS = 'retention_detections_days';

	/** Internal state, not shown as settings */
	public const INSTALLED_AT = 'installed_at';
	/** While in the future, low-value attempts are sampled because the attempts table is flooded */
	public const ATTEMPTS_FLOOD_UNTIL = 'attempts_flood_until';

	public const EXPORT_FORMATS = 'export_formats';
	public const BLOCKLIST_SOURCES = 'blocklist_sources';
	public const BLOCKLIST_MAX_ENTRIES = 'blocklist_max_entries';
	/** Internal: per list the active version and the last sync results */
	public const BLOCKLIST_STATE = 'blocklist_state';
	/** The groups whose members get the admin notifications */
	public const NOTIFY_ADMIN_GROUP = 'notify_admin_group';
	/** Detections of at least this severity are also emailed to them ("never" for no emails) */
	public const NOTIFY_ADMIN_EMAIL_MIN_SEVERITY = 'notify_admin_email_min_severity';
	/** Internal: until when a distributed credential stuffing attack counts as running */
	public const CS_DISTRIBUTED_UNTIL = 'cs_distributed_until';
	/** Internal: when the running distributed attack was last recorded as a detection */
	public const CS_DISTRIBUTED_DETECTED_AT = 'cs_distributed_detected_at';
	/** Internal: the detection of the running distributed attack */
	public const CS_DISTRIBUTED_DETECTION = 'cs_distributed_detection';
	/** Internal: when the instance-wide credential stuffing numbers were last evaluated, where no memory cache exists */
	public const CS_EVALUATED_AT = 'cs_evaluated_at';
	/** Internal: how many decoy credentials exist, so failed logins skip the lookup while there are none */
	public const DECOY_COUNT = 'decoy_count';
	/** A second administrator must approve every new administrator */
	public const ADMIN_CHANGE_REQUIRE_APPROVAL = 'admin_change_require_approval';
	/** Internal: when the watched settings were first recorded; 0 until then */
	public const CONFIG_WATCH_BASELINE = 'config_watch_baseline';

	/** Internal: when the running learning period started */
	public const LEARNING_STARTED_AT = 'learning_started_at';

	/** How often the administrators get the digest email: off, daily or weekly */
	public const DIGEST_FREQUENCY = 'digest_frequency';
	/** Whether a digest is also sent when nothing happened */
	public const DIGEST_SEND_QUIET = 'digest_send_quiet';
	/** Internal: the last digest sent, for the admin page */
	public const DIGEST_STATE = 'digest_state';
	/** Whether the typed events for webhooks carry the address */
	public const EVENTS_INCLUDE_IP = 'events_include_ip';
	/** Internal: detections deleted after their retention, counted per check, severity and enforcement, for the metrics' running total */
	public const DETECTIONS_RETIRED = 'detections_retired';

	/** Internal: until when sessions with an unconfirmed login may exist, so that resumed sessions are checked */
	public const STEP_UP_SESSIONS_UNTIL = 'step_up_sessions_until';
	/** The step-up policies for which a remembered device confirms a login */
	public const STEP_UP_KNOWN_DEVICE_OK_FOR = 'step_up_known_device_ok_for';
	/** Whether an administrator can approve a login that nothing else can confirm */
	public const STEP_UP_ADMIN_APPROVAL = 'step_up_admin_approval';
	/** Whether users may remember a browser after confirming a login */
	public const KNOWN_DEVICE_ENABLED = 'known_device_enabled';
	/** Days the login history and the security change log are kept */
	public const HISTORY_RETENTION_DAYS = 'history_retention_days';

	/** Whether the address risk score lowers limits and asks for confirmation (concept section 10.18) */
	public const RISK_ENABLED = 'risk_enabled';
	/** Networks whose addresses are never risky: the company's own networks and VPN */
	public const RISKY_NETWORK_OFFICE_NETWORKS = 'risky_network_office_networks';
	/** Groups whose members may log in from hosting and Tor networks without extra confirmation */
	public const RISKY_NETWORK_EXEMPT_GROUPS = 'risky_network_exempt_groups';
	/** Whether users see the intrusion detection part of their security settings */
	public const PERSONAL_PAGE_ENABLED = 'personal_page_enabled';
	/** Bans that ended up to this time have been flagged */
	public const BANS_FLAGGED_UNTIL = 'bans_flagged_until';
	/** Internal: the counts of active accounts and of those without a way to confirm a login, with when they were counted */
	public const COVERAGE_USERS = 'coverage_users';
	/** Internal: reserved names and decoy login names that are accounts by now, with when they were looked up */
	public const TRAP_NAME_COLLISIONS = 'trap_name_collisions';
	/** Internal: the protection level the limits were last set to (recommended, strict, relaxed), or custom after a change by hand */
	public const PROTECTION_LEVEL = 'protection_level';
	/** Internal: this server's own addresses seen in web requests, for cron and occ */
	public const SERVER_ADDRESSES = 'server_addresses';

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
				new ParamDefinition(self::LEARNING_DECOYS_ACT, ParamType::Bool, true),
				new ParamDefinition(self::LEARNING_NOTICE_SENT, ParamType::Int, 0, min: 0),
				// The three escalation levels: first block, repeat within the history window, and after that.
				new ParamDefinition(self::BAN_DURATION_1, ParamType::Duration, 14400, min: 300, max: 90 * 86400, preset: ParamPreset::BlockDuration),
				new ParamDefinition(self::BAN_DURATION_2, ParamType::Duration, 86400, min: 300, max: 90 * 86400, preset: ParamPreset::BlockDuration),
				new ParamDefinition(self::BAN_DURATION_3, ParamType::Duration, 604800, min: 300, max: 90 * 86400, preset: ParamPreset::BlockDuration),
				new ParamDefinition(self::BAN_HISTORY_DAYS, ParamType::Int, 30, min: 1, max: 365),
				new ParamDefinition(self::BAN_NET_AFTER, ParamType::Int, 3, min: 2, max: 256),
				new ParamDefinition(self::BAN_SHARED_IP_USERS, ParamType::Int, 5, min: 0, max: 10000),
				new ParamDefinition(self::RETENTION_DETECTIONS_DAYS, ParamType::Int, 90, min: 7, max: 730),
				new ParamDefinition(self::INSTALLED_AT, ParamType::Int, 0, min: 0),
				new ParamDefinition(self::ATTEMPTS_FLOOD_UNTIL, ParamType::Int, 0, min: 0),
				new ParamDefinition(self::EXPORT_FORMATS, ParamType::StringList, [], itemPattern: '/^(txt|nft|ipset|log)$/', maxItems: 4),
				new ParamDefinition(self::BLOCKLIST_SOURCES, ParamType::Json, '[]'),
				new ParamDefinition(self::BLOCKLIST_MAX_ENTRIES, ParamType::Int, 200000, min: 100, max: 500000),
				new ParamDefinition(self::BLOCKLIST_STATE, ParamType::Json, '{}'),
				new ParamDefinition(self::NOTIFY_ADMIN_GROUP, ParamType::StringList, ['admin'], itemPattern: '/^[^\x00-\x1f\x7f]{1,255}$/u', maxItems: 10),
				new ParamDefinition(self::NOTIFY_ADMIN_EMAIL_MIN_SEVERITY, ParamType::Choice, 'high', choices: ['low', 'medium', 'high', 'critical', 'never']),
				new ParamDefinition(self::CS_DISTRIBUTED_UNTIL, ParamType::Int, 0, min: 0),
				new ParamDefinition(self::CS_DISTRIBUTED_DETECTED_AT, ParamType::Int, 0, min: 0),
				new ParamDefinition(self::CS_DISTRIBUTED_DETECTION, ParamType::Int, 0, min: 0),
				new ParamDefinition(self::CS_EVALUATED_AT, ParamType::Int, 0, min: 0),
				new ParamDefinition(self::DECOY_COUNT, ParamType::Int, 0, min: 0),
				new ParamDefinition(self::ADMIN_CHANGE_REQUIRE_APPROVAL, ParamType::Bool, false),
				new ParamDefinition(self::CONFIG_WATCH_BASELINE, ParamType::Int, 0, min: 0),
				new ParamDefinition(self::DIGEST_FREQUENCY, ParamType::Choice, 'weekly', choices: ['off', 'daily', 'weekly']),
				new ParamDefinition(self::DIGEST_SEND_QUIET, ParamType::Bool, true),
				new ParamDefinition(self::DIGEST_STATE, ParamType::Json, '{}'),
				new ParamDefinition(self::EVENTS_INCLUDE_IP, ParamType::Bool, true),
				new ParamDefinition(self::LEARNING_STARTED_AT, ParamType::Int, 0, min: 0),
				new ParamDefinition(self::STEP_UP_SESSIONS_UNTIL, ParamType::Int, 0, min: 0),
				...array_map(
					static fn (StepUpPolicy $p): ParamDefinition => new ParamDefinition($p->settingKey(), ParamType::Choice, $p->defaultOutcome()->value, choices: NoMethodOutcome::values()),
					StepUpReasons::policies(),
				),
				new ParamDefinition(self::DETECTIONS_RETIRED, ParamType::Json, '{}'),
				new ParamDefinition(self::STEP_UP_KNOWN_DEVICE_OK_FOR, ParamType::StringList, KnownDeviceMethod::DEFAULT_POLICIES, itemPattern: KnownDeviceMethod::POLICY_PATTERN, maxItems: count(StepUpPolicy::cases())),
				new ParamDefinition(self::STEP_UP_ADMIN_APPROVAL, ParamType::Bool, false),
				new ParamDefinition(self::KNOWN_DEVICE_ENABLED, ParamType::Bool, true),
				new ParamDefinition(self::HISTORY_RETENTION_DAYS, ParamType::Int, 90, min: 7, max: 365),
				new ParamDefinition(self::RISK_ENABLED, ParamType::Bool, true),
				new ParamDefinition(self::RISKY_NETWORK_OFFICE_NETWORKS, ParamType::CidrList, [], maxItems: 100),
				new ParamDefinition(self::RISKY_NETWORK_EXEMPT_GROUPS, ParamType::StringList, [], itemPattern: '/^[^\x00-\x1f\x7f]{1,255}$/u', maxItems: 20),
				new ParamDefinition(self::PERSONAL_PAGE_ENABLED, ParamType::Bool, true),
				new ParamDefinition(self::BANS_FLAGGED_UNTIL, ParamType::Int, 0, min: 0),
				new ParamDefinition(self::COVERAGE_USERS, ParamType::Json, '{}'),
				new ParamDefinition(self::TRAP_NAME_COLLISIONS, ParamType::Json, '{}'),
				new ParamDefinition(self::PROTECTION_LEVEL, ParamType::Choice, ProtectionLevel::Recommended->value, choices: array_map(static fn (ProtectionLevel $level): string => $level->value, ProtectionLevel::cases())),
				new ParamDefinition(self::SERVER_ADDRESSES, ParamType::StringList, [], itemPattern: '/^[0-9a-f.:]{2,45}$/', maxItems: ServerAddresses::MAX_REMEMBERED),
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
	 * The check whose rules a global setting must also pass when it is written,
	 * for settings that belong to one check.
	 *
	 * @return ?class-string<IValidatesParams>
	 */
	public static function validatedBy(string $name): ?string {
		return match ($name) {
			self::ADMIN_CHANGE_REQUIRE_APPROVAL => AdminChange::class,
			default => null,
		};
	}

	/**
	 * Settings that hold internal state and are never set by an admin.
	 */
	public static function isInternal(string $name): bool {
		return in_array($name, [
			self::INSTALLED_AT, self::LEARNING_NOTICE_SENT, self::ATTEMPTS_FLOOD_UNTIL,
			self::BLOCKLIST_STATE,
			self::CS_DISTRIBUTED_UNTIL, self::CS_DISTRIBUTED_DETECTED_AT, self::CS_DISTRIBUTED_DETECTION, self::CS_EVALUATED_AT,
			self::DECOY_COUNT,
			self::CONFIG_WATCH_BASELINE,
			self::DIGEST_STATE,
			self::LEARNING_STARTED_AT,
			self::STEP_UP_SESSIONS_UNTIL,
			self::DETECTIONS_RETIRED,
			self::BANS_FLAGGED_UNTIL,
			self::COVERAGE_USERS,
			self::TRAP_NAME_COLLISIONS,
			self::PROTECTION_LEVEL,
			self::SERVER_ADDRESSES,
		], true);
	}
}
