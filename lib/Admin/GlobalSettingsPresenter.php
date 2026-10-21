<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Admin;

use OCA\IntrusionDetection\Check\ParamText;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\IL10N;

/**
 * The global settings as the admin page shows and edits them: every setting
 * an admin may change, with its value, rules, texts and the page group it
 * belongs to. Internal state is never included.
 *
 * @psalm-import-type IntrusionDetectionGlobalSetting from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionSettings from ResponseDefinitions
 */
class GlobalSettingsPresenter {
	/** The master switch, shown on its own with a confirmation */
	public const GROUP_MASTER = 'master';
	public const GROUP_LEARNING = 'learning';
	/** Shown on the Blocks tab, next to the escalation explanation */
	public const GROUP_BLOCKS = 'blocks';
	public const GROUP_PRIVACY = 'privacy';
	/** Who is told about detections, and how */
	public const GROUP_NOTIFICATIONS = 'notifications';
	/** Settings without a group are listed on the Advanced tab */
	public const GROUP_OTHER = 'other';

	/** Changed through the learning mode endpoint only, so every change is explained and audited as such */
	private const MANAGED_ELSEWHERE = [GlobalSettings::LEARNING_UNTIL, GlobalSettings::BLOCKLIST_SOURCES];

	public function __construct(
		private readonly GlobalSettings $globals,
		private readonly Settings $settings,
	) {
	}

	/**
	 * Whether an admin may change the setting through the settings endpoint.
	 */
	public function isEditable(string $name): bool {
		return $this->globals->get($name) !== null
			&& !GlobalSettings::isInternal($name)
			&& !GlobalSettings::isUnlisted($name)
			&& !in_array($name, self::MANAGED_ELSEWHERE, true);
	}

	/**
	 * @return IntrusionDetectionSettings
	 */
	public function present(IL10N $l): array {
		$settings = [];
		foreach ($this->globals->all() as $name => $definition) {
			if (!$this->isEditable($name)) {
				continue;
			}
			[$text, $group] = $this->describe($name, $l);
			$settings[] = array_merge($definition->toArray(), [
				'value' => $this->settings->global($name),
				'label' => $text->label,
				'help' => $text->help,
				'unit' => $text->unit,
				'group' => $group,
			]);
		}
		return [
			'settings' => $settings,
			'templates' => [
				'escalation' => $l->t('First block: {ban_duration_1}. If the same address is blocked again within {ban_history_days} days: {ban_duration_2}. After that: {ban_duration_3}. When {ban_net_after} addresses of the same /24 network are blocked within 24 hours, the whole network is blocked. IPv6 addresses are always blocked with their /64 network, because one device usually controls all of it.'),
				'safetyValve' => $l->t('An address from which at least {ban_shared_ip_users} different people logged in successfully in the last 24 hours is never blocked. That is typical for an office network or a reverse proxy, and blocking it would lock everyone out. You are notified instead.'),
				'safetyValveOff' => $l->t('The safety valve is off: an address is blocked even when many people log in from it. A company network or a misconfigured reverse proxy could lock everyone out.'),
				'neverBlocked' => $l->t('Addresses on the brute-force allowlist and the server\'s own addresses are never blocked.'),
			],
		];
	}

	/**
	 * @return array{0: ParamText, 1: string}
	 */
	private function describe(string $name, IL10N $l): array {
		return match ($name) {
			GlobalSettings::ENABLED => [new ParamText(
				$l->t('Intrusion detection'),
				$l->t('When it is off, no check runs, nothing is recorded and existing blocks are not enforced.'),
			), self::GROUP_MASTER],
			GlobalSettings::LEARNING_DECOYS_ACT => [new ParamText(
				$l->t('Decoys act while learning'),
				$l->t('Decoy credentials are planted on purpose, so nobody uses one by accident. Leave this on to block at once, even in learning mode.'),
			), self::GROUP_LEARNING],
			GlobalSettings::BAN_DURATION_1 => [new ParamText(
				$l->t('First block'),
				$l->t('How long an address is blocked the first time.'),
			), self::GROUP_BLOCKS],
			GlobalSettings::BAN_DURATION_2 => [new ParamText(
				$l->t('Second block'),
				$l->t('When the same address is blocked again within the history window.'),
			), self::GROUP_BLOCKS],
			GlobalSettings::BAN_DURATION_3 => [new ParamText(
				$l->t('Repeat offenders'),
				$l->t('Every block after the second one within the history window.'),
			), self::GROUP_BLOCKS],
			GlobalSettings::BAN_HISTORY_DAYS => [new ParamText(
				$l->t('History window'),
				$l->t('How long earlier blocks count when deciding how long the next one lasts.'),
				$l->t('days'),
			), self::GROUP_BLOCKS],
			GlobalSettings::BAN_NET_AFTER => [new ParamText(
				$l->t('Block the whole network after'),
				$l->t('When this many addresses of one /24 network are blocked within 24 hours, the network is blocked too.'),
				$l->t('addresses'),
			), self::GROUP_BLOCKS],
			GlobalSettings::BAN_SHARED_IP_USERS => [new ParamText(
				$l->t('Never block addresses shared by'),
				$l->t('Addresses from which this many different people logged in successfully in the last 24 hours are not blocked. 0 turns this safety valve off.'),
				$l->t('people'),
			), self::GROUP_BLOCKS],
			GlobalSettings::FLAG_DURATION => [new ParamText(
				$l->t('Extra confirmation after an attack'),
				$l->t('How long successful logins from an attacking address need extra confirmation.'),
			), self::GROUP_BLOCKS],
			GlobalSettings::RETENTION_DETECTIONS_DAYS => [new ParamText(
				$l->t('Keep detections for'),
				$l->t('Older detections are deleted. Blocks are kept 30 days after they end, for escalation.'),
				$l->t('days'),
			), self::GROUP_PRIVACY],
			GlobalSettings::EXPORT_FORMATS => [new ParamText(
				$l->t('Firewall export formats'),
				$l->t('The files written for your firewall or fail2ban whenever a block changes. They are only written when an export directory is set in config.php.'),
			), self::GROUP_BLOCKS],
			GlobalSettings::BLOCKLIST_SYNC_INTERVAL => [new ParamText(
				$l->t('Download lists every'),
				$l->t('How often the enabled blocklists and network lists are downloaded again. A list can set its own interval.'),
			), self::GROUP_BLOCKS],
			GlobalSettings::BLOCKLIST_MAX_ENTRIES => [new ParamText(
				$l->t('Largest accepted list'),
				$l->t('A downloaded list with more entries than this is refused, so a broken or hostile list cannot fill the database.'),
				$l->t('entries'),
			), self::GROUP_BLOCKS],
			GlobalSettings::NOTIFY_ADMIN_GROUP => [new ParamText(
				$l->t('Notify these groups'),
				$l->t('Members of these groups get the administrator notifications.'),
			), self::GROUP_NOTIFICATIONS],
			GlobalSettings::NOTIFY_ADMIN_EMAIL_MIN_SEVERITY => [new ParamText(
				$l->t('Also email from severity'),
				$l->t('Detections of this severity or higher are also emailed, at most once per check and hour. "never" sends no emails.'),
			), self::GROUP_NOTIFICATIONS],
			default => [new ParamText(ucfirst(str_replace('_', ' ', $name))), self::GROUP_OTHER],
		};
	}
}
