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
use OCA\IntrusionDetection\Check\ParamType;

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
	public const FLAG_DURATION = 'flag_duration';
	public const RETENTION_DETECTIONS_DAYS = 'retention_detections_days';

	/** Internal state, not shown as settings */
	public const BAN_VERSION = 'ban_version';
	public const INSTALLED_AT = 'installed_at';
	/** While in the future, low-value attempts are sampled because the attempts table is flooded */
	public const ATTEMPTS_FLOOD_UNTIL = 'attempts_flood_until';

	public const EXPORT_FORMATS = 'export_formats';
	public const BLOCKLIST_SOURCES = 'blocklist_sources';
	public const BLOCKLIST_SYNC_INTERVAL = 'blocklist_sync_interval';
	public const BLOCKLIST_MAX_ENTRIES = 'blocklist_max_entries';
	/** Internal: per list the active version and the last sync results */
	public const BLOCKLIST_STATE = 'blocklist_state';
	/** Internal: the last firewall export */
	public const EXPORT_STATE = 'export_state';
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
	/** Internal: how many decoy credentials exist, so failed logins skip the lookup while there are none */
	public const DECOY_COUNT = 'decoy_count';
	/** A second administrator must approve every new administrator */
	public const ADMIN_CHANGE_REQUIRE_APPROVAL = 'admin_change_require_approval';
	/** Seconds a request for approval waits before it expires */
	public const ADMIN_CHANGE_APPROVAL_TTL = 'admin_change_approval_ttl';
	/** Internal: when the watched settings were first recorded; 0 until then */
	public const CONFIG_WATCH_BASELINE = 'config_watch_baseline';

	/** Only shown and used while config.php has `intrusion_detection.contribution_available` */
	public const CONTRIBUTE_ENABLED = 'contribute_enabled';
	public const CONTRIBUTE_URL = 'contribute_url';
	/** Internal: the random contributor id sent with every report */
	public const CONTRIBUTE_ID = 'contribute_id';
	/** Internal: the last run, its result and the end of the last window sent */
	public const CONTRIBUTE_STATE = 'contribute_state';
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
				new ParamDefinition(self::BAN_DURATION_1, ParamType::Duration, 14400, min: 300, max: 90 * 86400),
				new ParamDefinition(self::BAN_DURATION_2, ParamType::Duration, 86400, min: 300, max: 90 * 86400),
				new ParamDefinition(self::BAN_DURATION_3, ParamType::Duration, 604800, min: 300, max: 90 * 86400),
				new ParamDefinition(self::BAN_HISTORY_DAYS, ParamType::Int, 30, min: 1, max: 365),
				new ParamDefinition(self::BAN_NET_AFTER, ParamType::Int, 3, min: 2, max: 256),
				new ParamDefinition(self::BAN_SHARED_IP_USERS, ParamType::Int, 5, min: 0, max: 10000),
				new ParamDefinition(self::FLAG_DURATION, ParamType::Duration, 86400, min: 3600, max: 30 * 86400),
				new ParamDefinition(self::RETENTION_DETECTIONS_DAYS, ParamType::Int, 90, min: 7, max: 730),
				new ParamDefinition(self::BAN_VERSION, ParamType::Int, 0, min: 0),
				new ParamDefinition(self::INSTALLED_AT, ParamType::Int, 0, min: 0),
				new ParamDefinition(self::ATTEMPTS_FLOOD_UNTIL, ParamType::Int, 0, min: 0),
				new ParamDefinition(self::EXPORT_FORMATS, ParamType::StringList, [], itemPattern: '/^(txt|nft|ipset|log)$/', maxItems: 4),
				new ParamDefinition(self::BLOCKLIST_SOURCES, ParamType::Json, '[]'),
				new ParamDefinition(self::BLOCKLIST_SYNC_INTERVAL, ParamType::Duration, 21600, min: 3600, max: 7 * 86400),
				new ParamDefinition(self::BLOCKLIST_MAX_ENTRIES, ParamType::Int, 200000, min: 100, max: 500000),
				new ParamDefinition(self::BLOCKLIST_STATE, ParamType::Json, '{}'),
				new ParamDefinition(self::EXPORT_STATE, ParamType::Json, '{}'),
				new ParamDefinition(self::NOTIFY_ADMIN_GROUP, ParamType::StringList, ['admin'], itemPattern: '/^[^\x00-\x1f\x7f]{1,255}$/u', maxItems: 10),
				new ParamDefinition(self::NOTIFY_ADMIN_EMAIL_MIN_SEVERITY, ParamType::Choice, 'high', choices: ['low', 'medium', 'high', 'critical', 'never']),
				new ParamDefinition(self::CS_DISTRIBUTED_UNTIL, ParamType::Int, 0, min: 0),
				new ParamDefinition(self::CS_DISTRIBUTED_DETECTED_AT, ParamType::Int, 0, min: 0),
				new ParamDefinition(self::CS_DISTRIBUTED_DETECTION, ParamType::Int, 0, min: 0),
				new ParamDefinition(self::DECOY_COUNT, ParamType::Int, 0, min: 0),
				new ParamDefinition(self::CONTRIBUTE_ENABLED, ParamType::Bool, false),
				new ParamDefinition(self::CONTRIBUTE_URL, ParamType::Text, '', maxItemLength: 2048),
				new ParamDefinition(self::CONTRIBUTE_ID, ParamType::Text, '', itemPattern: '/^([a-z0-9]{32})?$/'),
				new ParamDefinition(self::CONTRIBUTE_STATE, ParamType::Json, '{}'),
				new ParamDefinition(self::ADMIN_CHANGE_REQUIRE_APPROVAL, ParamType::Bool, false),
				new ParamDefinition(self::ADMIN_CHANGE_APPROVAL_TTL, ParamType::Duration, 604800, min: 3600, max: 30 * 86400),
				new ParamDefinition(self::CONFIG_WATCH_BASELINE, ParamType::Int, 0, min: 0),
				new ParamDefinition(self::DIGEST_FREQUENCY, ParamType::Choice, 'weekly', choices: ['off', 'daily', 'weekly']),
				new ParamDefinition(self::DIGEST_SEND_QUIET, ParamType::Bool, true),
				new ParamDefinition(self::DIGEST_STATE, ParamType::Json, '{}'),
				new ParamDefinition(self::EVENTS_INCLUDE_IP, ParamType::Bool, true),
				new ParamDefinition(self::LEARNING_STARTED_AT, ParamType::Int, 0, min: 0),
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
			self::BAN_VERSION, self::INSTALLED_AT, self::LEARNING_NOTICE_SENT, self::ATTEMPTS_FLOOD_UNTIL,
			self::BLOCKLIST_STATE, self::EXPORT_STATE,
			self::CS_DISTRIBUTED_UNTIL, self::CS_DISTRIBUTED_DETECTED_AT, self::CS_DISTRIBUTED_DETECTION,
			self::DECOY_COUNT,
			self::CONTRIBUTE_ID, self::CONTRIBUTE_STATE,
			self::CONFIG_WATCH_BASELINE,
			self::DIGEST_STATE,
			self::LEARNING_STARTED_AT,
		], true);
	}

	/**
	 * Settings that generic listings leave out, because a dedicated service
	 * shows them only when the feature is available on this server.
	 */
	public static function isUnlisted(string $name): bool {
		return in_array($name, [self::CONTRIBUTE_ENABLED, self::CONTRIBUTE_URL], true);
	}
}
