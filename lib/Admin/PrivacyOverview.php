<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Admin;

use OCA\IntrusionDetection\AdminChange\ApprovalService;
use OCA\IntrusionDetection\Blocklist\BlocklistSource;
use OCA\IntrusionDetection\Blocklist\BlocklistSync;
use OCA\IntrusionDetection\Blocklist\ContributionOverview;
use OCA\IntrusionDetection\Blocklist\SourceRepository;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\DataKind;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\BlocklistStatMapper;
use OCA\IntrusionDetection\Detection\AttemptRecorder;
use OCA\IntrusionDetection\Personal\FailedLoginStats;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCA\IntrusionDetection\Takeover\LockLinks;
use OCP\IL10N;

/**
 * The "Data and privacy" tab: every kind of data the installed checks store
 * (what, why, how long, where), what leaves the server, and the note on the
 * GDPR. The kinds come from the checks' `stores`, so a check added later
 * shows its data here without changes to this class.
 *
 * Retention texts may contain `{setting}` placeholders, which the page fills
 * in live while the retention settings are edited.
 *
 * @psalm-import-type IntrusionDetectionPrivacy from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionStoredData from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionOutgoingData from ResponseDefinitions
 */
class PrivacyOverview {
	/** Data the app keeps for features rather than for one check, always listed */
	public const FEATURE_DATA = [DataKind::LoginHistory, DataKind::KnownDevices, DataKind::TrustedNetworks, DataKind::UnconfirmedSessions, DataKind::FailedLoginDays, DataKind::RiskySessions, DataKind::Lockdowns];

	public function __construct(
		private readonly CheckRegistry $registry,
		private readonly Settings $settings,
		private readonly SourceRepository $sources,
		private readonly ContributionOverview $contribution,
	) {
	}

	/**
	 * @return IntrusionDetectionPrivacy
	 */
	public function get(IL10N $l): array {
		return [
			'stored' => $this->stored($l),
			'outgoing' => $this->outgoing($l),
			'contribution' => $this->contribution->get($l),
			'gdpr' => [
				$l->t('IP addresses and account names are personal data under the GDPR. Processing them to protect your server is usually a legitimate interest (Article 6(1)(f)), but you should document this decision in your records of processing activities and mention it in your privacy notice.'),
				$l->t('Everything listed here stays in your database or memory cache and is deleted automatically after the time shown. Passwords are never stored; fingerprints of them cannot be turned back into a password and are useless without the secret in config.php.'),
			],
		];
	}

	/**
	 * @return list<IntrusionDetectionStoredData>
	 */
	public function stored(IL10N $l): array {
		/** @var array<string, list<string>> $users check names by data kind */
		$users = [];
		foreach ($this->registry->all() as $check) {
			foreach ($check->stores as $kind) {
				$users[$kind->value][] = $check->texts($l)->name;
			}
		}
		$rows = [];
		foreach (DataKind::cases() as $kind) {
			if (!isset($users[$kind->value]) && !in_array($kind, self::FEATURE_DATA, true)) {
				continue;
			}
			$rows[] = array_merge(['id' => $kind->value], $this->describe($kind, $l), ['checks' => array_values(array_unique($users[$kind->value] ?? []))]);
		}
		$rows[] = [
			'id' => 'alert_counters',
			'name' => $l->t('Notification counters'),
			'what' => $l->t('The check, the address or account an alert was about, and how often it fired within the hour.'),
			'why' => $l->t('So that an attack turns into one notification with a counter rather than thousands.'),
			'retention' => $l->t('30 days'),
			'where' => 'ids_alerts',
			'checks' => [],
		];
		return $rows;
	}

	/**
	 * @return array{name: string, what: string, why: string, retention: string, where: string}
	 */
	private function describe(DataKind $kind, IL10N $l): array {
		return match ($kind) {
			DataKind::FailedAttempts => [
				'name' => $l->t('Failed logins and share accesses'),
				'what' => $l->t('The address, a fingerprint of the account name and of the password, the account if it exists, and the time.'),
				'why' => $l->t('To recognise attacks: many failures from one address, one password tried against many accounts, one account attacked from many places.'),
				'retention' => $l->n('%n hour', '%n hours', intdiv(AttemptRecorder::RETENTION, 3600)),
				'where' => 'ids_attempts',
			],
			DataKind::SuccessfulLogins => [
				'name' => $l->t('Successful logins'),
				'what' => $l->t('The address, the account and the hour.'),
				'why' => $l->t('So that an address many people log in from, such as an office network, is never blocked.'),
				'retention' => $l->t('24 hours'),
				'where' => 'ids_logins',
			],
			DataKind::Detections => [
				'name' => $l->t('Detections'),
				'what' => $l->t('The check, the address, the account concerned, the measured values, what was done, and the time.'),
				'why' => $l->t('To explain every decision on this page and in notifications, and to find repeated attacks.'),
				'retention' => $l->t('{retention_detections_days} days'),
				'where' => 'ids_detections',
			],
			DataKind::Bans => [
				'name' => $l->t('Blocks'),
				'what' => $l->t('The address or network, the reference, the level, and who lifted it and why.'),
				'why' => $l->t('To refuse blocked addresses, and to block an address longer when it comes back.'),
				'retention' => $l->t('While active, then {ban_history_days} days, but at least 30 days'),
				'where' => 'ids_bans',
			],
			DataKind::Flags => [
				'name' => $l->t('Marked addresses and accounts'),
				'what' => $l->t('Addresses after an attack, accounts under attack, fingerprints of passwords that were tried against many accounts, and the name of an attack tool an address used for a failed login.'),
				'why' => $l->t('So that a successful login after an attack needs extra confirmation, and for the address risk score.'),
				'retention' => $l->t('{flag_duration}; password fingerprints and attack tools 24 hours'),
				'where' => 'ids_flags, ids_protected_accounts',
			],
			DataKind::LoginHistory => [
				'name' => $l->t('Login history'),
				'what' => $l->t('Per successful login: the account, the time, the address and its network, the browser or app (at most 200 characters), how the account logged in, and how the login was confirmed.'),
				'why' => $l->t('So that users can see their recent logins, and so that an incident can be reconstructed. Apps that log in with every request are recorded at most once an hour.'),
				'retention' => $l->t('{history_retention_days} days'),
				'where' => 'ids_login_history',
			],
			DataKind::SecurityChanges => [
				'name' => $l->t('Security changes'),
				'what' => $l->t('The kind of change to an account (email address, password, second factor, app passwords), who made it, the session, the address and the time. Email addresses only masked; the full previous address encrypted for one day.'),
				'why' => $l->t('To recognise an account takeover, where an attacker changes the email address or password one after the other, to reach the previous address with the lock link, and to show users and incident reports what changed.'),
				'retention' => $l->t('{history_retention_days} days; the previous address 1 day'),
				'where' => 'ids_security_changes',
			],
			DataKind::KnownDevices => [
				'name' => $l->t('Known devices'),
				'what' => $l->t('For browsers a user chose to remember after confirming a login: a keyed fingerprint of a random cookie, the browser and system family, the network, and when it was first and last used.'),
				'why' => $l->t('So that people logging in from their own device are not asked to confirm again, where the reason allows it.'),
				'retention' => $l->t('{known_device_duration} after the last use, or until the user removes it'),
				'where' => 'ids_known_devices',
			],
			DataKind::TokenOrigins => [
				'name' => $l->t('App password origins'),
				'what' => $l->t('Where each app password was created: the address and the time.'),
				'why' => $l->t('To recognise an app password that is used from somewhere else at the same time.'),
				'retention' => $l->t('30 days'),
				'where' => 'ids_token_origin',
			],
			DataKind::Decoys => [
				'name' => $l->t('Decoy credentials'),
				'what' => $l->t('The label, the optional login name, a keyed fingerprint of the secret, and when it was last used.'),
				'why' => $l->t('To recognise anyone who uses a decoy. The secret itself is never stored.'),
				'retention' => $l->t('Until you delete the decoy'),
				'where' => 'ids_decoys',
			],
			DataKind::BlocklistRanges => [
				'name' => $l->t('Blocklists and network lists'),
				'what' => $l->t('The address ranges of the lists you enabled, and per list and day the number of matches and the last %s matched addresses.', [(string)BlocklistStatMapper::SAMPLE_SIZE]),
				'why' => $l->t('To refuse or recognise addresses on these lists without asking an outside service.'),
				'retention' => $l->n('Ranges until the list is switched off; matches %n day', 'Ranges until the list is switched off; matches %n days', BlocklistSync::STATS_DAYS),
				'where' => 'ids_blocklist_ranges, ids_blocklist_stats',
			],
			DataKind::RequestExcerpts => [
				'name' => $l->t('Excerpts of suspicious requests'),
				'what' => $l->t('The parameter name, the matched signatures and at most 200 characters of the value, never from password fields.'),
				'why' => $l->t('To show exactly what matched, so you can tell an attack from a false alarm.'),
				'retention' => $l->t('{retention_detections_days} days, with the detection'),
				'where' => 'ids_detections',
			],
			DataKind::CacheCounters => [
				'name' => $l->t('Short-lived counters'),
				'what' => $l->t('Counters per address or account in the memory cache.'),
				'why' => $l->t('To recognise fast attacks without writing to the database on every request.'),
				'retention' => $l->t('Minutes, at most an hour'),
				'where' => $l->t('memory cache'),
			],
			DataKind::AccountState => [
				'name' => $l->t('Account state'),
				'what' => $l->t('Per account: when the password was last checked against the breach list, whether it was found there, and whether a new password is required.'),
				'why' => $l->t('To check each password only as often as needed, and to ask for a new one at the next login.'),
				'retention' => $l->t('Until the account is deleted'),
				'where' => $l->t('user preferences'),
			],
			DataKind::ConfigSnapshot => [
				'name' => $l->t('Settings snapshot'),
				'what' => $l->t('A keyed hash of each watched security setting, and its value where it is not secret.'),
				'why' => $l->t('To recognise security settings that were changed outside the web interface.'),
				'retention' => $l->t('Replaced at every check'),
				'where' => 'ids_config_snapshot',
			],
			DataKind::Approvals => [
				'name' => $l->t('Approval requests'),
				'what' => $l->t('Who asked for which change, who decided, and when.'),
				'why' => $l->t('So that a second administrator can approve new administrators.'),
				'retention' => $l->n('%n day after the decision', '%n days after the decision', ApprovalService::RETENTION_DAYS),
				'where' => 'ids_approvals',
			],
			DataKind::TrustedNetworks => [
				'name' => $l->t('Trusted networks'),
				'what' => $l->t('Per account: the networks the user confirmed as their own with "Yes, it was me", and when.'),
				'why' => $l->t('So that logins from these networks are not asked for an extra confirmation again.'),
				'retention' => $l->n('%n day, or until the user removes the network', '%n days, or until the user removes the network', intdiv($this->settings->getInt(GlobalSettings::TRUSTED_NETWORK_DURATION), 86400)),
				'where' => 'ids_trusted_networks',
			],
			DataKind::UnconfirmedSessions => [
				'name' => $l->t('Unconfirmed logins'),
				'what' => $l->t('A keyed fingerprint of each session whose login still waits for its confirmation or was refused, never the session id itself.'),
				'why' => $l->t('So that such a session cannot skip the confirmation by coming back through its remember-me cookie.'),
				'retention' => $l->t('Until the login is confirmed or ended, at most as long as a remembered login lasts'),
				'where' => 'ids_step_up_sessions',
			],
			DataKind::LockLinks => [
				'name' => $l->t('Lock links'),
				'what' => $l->t('Per link: the account, a keyed fingerprint of the link (never the link itself), the masked address it was sent to, and when it was used and from which address.'),
				'why' => $l->t('So that the owner of an account\'s previous email address can lock the account once with the link from the email.'),
				'retention' => $l->n('%n day', '%n days', intdiv(LockLinks::TTL, 86400)),
				'where' => 'ids_lock_links',
			],
			DataKind::SecureAccountProgress => [
				'name' => $l->t('"Secure my account" progress'),
				'what' => $l->t('Per account: when the checklist started and why, which steps are done, and when it was finished.'),
				'why' => $l->t('To guide a user through securing their account, and to show you how far they got.'),
				'retention' => $l->t('Until the account is deleted'),
				'where' => $l->t('user preferences'),
			],
			DataKind::FailedLoginDays => [
				'name' => $l->t('Failed logins per account and day'),
				'what' => $l->t('For each existing account: how many logins failed per hour of a day, and up to 20 addresses they came from with the time of their last failure. Only while users see their security events.'),
				'why' => $l->t('So that users can see on their security page how often someone tried to log in to their account, and from where.'),
				'retention' => $l->n('%n day', '%n days', FailedLoginStats::RETENTION_DAYS),
				'where' => 'ids_user_daily',
			],
			DataKind::RiskySessions => [
				'name' => $l->t('Sessions that must confirm'),
				'what' => $l->t('The database id of a session\'s token (never the token), its account, and the check that made it risky.'),
				'why' => $l->t('So that a session a check found suspicious later must confirm sensitive actions on every web server.'),
				'retention' => $l->t('As long as the session could last'),
				'where' => 'ids_risky_sessions',
			],
			DataKind::Lockdowns => [
				'name' => $l->t('Lockdown history'),
				'what' => $l->t('When each lockdown started and ended, who started and ended it, the reason given and its effects.'),
				'why' => $l->t('So that you can see later why logins needed confirmation at that time, and for incident reports.'),
				'retention' => $l->n('%n day after it ended', '%n days after it ended', $this->settings->getInt(GlobalSettings::RETENTION_DETECTIONS_DAYS)),
				'where' => 'ids_lockdowns',
			],
		};
	}

	/**
	 * @return list<IntrusionDetectionOutgoingData>
	 */
	public function outgoing(IL10N $l): array {
		$outgoing = [];
		foreach ($this->registry->configurable() as $check) {
			if (!$check->sendsData) {
				continue;
			}
			$outgoing[] = [
				'id' => 'check:' . $check->id,
				'name' => $check->texts($l)->name,
				'text' => $check->texts($l)->data,
				'active' => $this->settings->modeState($check->id)->runs(),
				'items' => [],
			];
		}
		$enabled = $this->sources->enabled();
		$outgoing[] = [
			'id' => 'blocklists',
			'name' => $l->t('Blocklist downloads'),
			'text' => $l->t('Nextcloud downloads the lists you enabled from their publishers. Nothing about your server or your users is sent; the publisher sees a download from your server\'s address.'),
			'active' => $enabled !== [],
			'items' => array_map(static fn (BlocklistSource $source): string => $source->name, $enabled),
		];
		return $outgoing;
	}
}
