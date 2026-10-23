<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Admin;

use OCA\IntrusionDetection\AdminChange\ApprovalService;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\PurgeRetention;
use OCA\IntrusionDetection\Confirm\EmailCodes;
use OCA\IntrusionDetection\Confirm\LoginConfirmations;
use OCA\IntrusionDetection\Confirm\Methods\AdminApprovalMethod;
use OCA\IntrusionDetection\Confirm\NoMethodOutcome;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Definition\ParamText;
use OCA\IntrusionDetection\Explain\TextRenderer;
use OCA\IntrusionDetection\KnownDevice\KnownDevices;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCA\IntrusionDetection\Risk\RiskAssessment;
use OCA\IntrusionDetection\Risk\RiskScorer;
use OCA\IntrusionDetection\StaleCredential\StaleCredentials;
use OCA\IntrusionDetection\TrustedNetwork\TrustedNetworks;
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
	/** Shown on the Blocks tab, next to the escalation explanation */
	public const GROUP_BLOCKS = 'blocks';
	public const GROUP_PRIVACY = 'privacy';
	/** Who is told about detections, and how */
	public const GROUP_NOTIFICATIONS = 'notifications';
	/** A second administrator approves new administrators */
	public const GROUP_APPROVALS = 'approvals';
	/** Shown in the firewall export panel of the Blocks tab */
	public const GROUP_EXPORT = 'export';
	/** Extra confirmation of risky logins */
	public const GROUP_STEP_UP = 'step_up';
	/** Settings without a group are listed under "Other" on the Settings tab */
	public const GROUP_OTHER = 'other';
	/** The address risk score, shown in its card on the Protection tab */
	public const GROUP_RISK = 'risk';
	/** Trusted networks and exempt groups, shown in the card of the hosting and Tor networks check */
	public const GROUP_RISKY_NETWORK = 'risky_network';

	public function __construct(
		private readonly GlobalSettings $globals,
		private readonly AppSettings $settings,
	) {
	}

	/**
	 * Whether an admin may change the setting through the settings endpoint.
	 */
	public function isEditable(string $name): bool {
		return $this->globals->isEditable($name);
	}

	/**
	 * The label an admin sees for a global setting, e.g. "First block"; null
	 * for a name that is not a global setting.
	 */
	public function label(string $name, IL10N $l): ?string {
		return $this->globals->get($name) === null ? null : $this->describe($name, $l)[0]->label;
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
				'choices' => $definition->choiceLabels($l, $this->choiceLabels($l)),
				'value' => $this->settings->value($name),
				'label' => $text->label,
				'help' => $text->help,
				'unit' => $text->unit,
				'group' => $group,
				'locked' => $this->settings->isLockedSetting($name),
			]);
		}
		return [
			'settings' => $settings,
			'templates' => [
				'escalation' => $l->t('First block: {ban_duration_1}. If the same address is blocked again within {ban_history_days} days: {ban_duration_2}. After that: {ban_duration_3}. When {ban_net_after} addresses of the same /24 network are blocked within 24 hours, the whole network is blocked. IPv6 addresses are always blocked with their /64 network, because one device usually controls all of it. When {ban_net_after} of these /64 networks of one /56 are blocked within 24 hours, the /56 is blocked; when {ban_net_after} times {ban_net_after} of one /48 are, the /48.'),
				'safetyValve' => $l->t('An address from which at least {ban_shared_ip_users} different people whose accounts are at least 3 days old (or administrators) logged in successfully in the last 24 hours is never blocked, and neither is a network from which that many people logged in. Accounts registered in the last days do not count, so nobody can open the valve by creating a few. That is typical for an office network or a reverse proxy, and blocking it would lock everyone out. You are notified instead.'),
				'safetyValveOff' => $l->t('The safety valve is off: an address is blocked even when many people log in from it. A company network or a misconfigured reverse proxy could lock everyone out.'),
				'neverBlocked' => $l->t('Addresses on the brute-force allowlist and the server\'s own addresses are never blocked, and no network that contains one. Checks also never block an address an administrator logged in from in the last 7 days (except for trap URLs and injection probes), nor, for attacks on one account, an address from which that account confirmed a login in the last 7 days (with a second factor, an email code, an administrator\'s approval or a remembered device), nor a private address many people or an administrator log in from while no trusted proxies are configured. You can still block these by hand.'),
				'confirmationTimes' => $l->t('Email codes are valid for %1$s. A login that is not confirmed within %2$s is ended, and the user is told. A login waits for an administrator\'s approval at most %3$s. When a user answers "Yes, it was me", their network is trusted for %4$s.', [
					TextRenderer::duration(EmailCodes::TTL, $l),
					TextRenderer::duration(LoginConfirmations::SESSION_TTL, $l),
					TextRenderer::duration(AdminApprovalMethod::TTL, $l),
					TextRenderer::duration(TrustedNetworks::DURATION, $l),
				]),
				'knownDeviceTime' => $l->t('A remembered browser that is not used for %s is forgotten.', [TextRenderer::duration(KnownDevices::DURATION, $l)]),
				'riskPoints' => $l->t('Points: %1$s for an attack tool or scripting library on a failed login in the last 24 hours, %2$s for a Tor exit node, %3$s for a cloud hosting network, %4$s for a blocklist that only observes, %5$s for a trap URL or reserved name in the last 24 hours, %6$s for an address marked after an attack, %7$s for every %8$s failed logins in the last hour (at most %9$s times), and %10$s for a trusted network.', [
					(string)RiskScorer::POINTS[RiskAssessment::FACT_ATTACK_TOOL],
					(string)RiskScorer::POINTS[RiskAssessment::FACT_TOR],
					(string)RiskScorer::POINTS[RiskAssessment::FACT_HOSTING],
					(string)RiskScorer::POINTS[RiskAssessment::FACT_BLOCKLIST],
					(string)RiskScorer::POINTS[RiskAssessment::FACT_TRAP],
					(string)RiskScorer::POINTS[RiskAssessment::FACT_FLAGGED],
					(string)RiskScorer::POINTS[RiskAssessment::FACT_FAILURES],
					(string)RiskScorer::FAILURES_PER_STEP,
					(string)RiskScorer::MAX_FAILURE_STEPS,
					(string)RiskScorer::POINTS[RiskAssessment::FACT_OFFICE],
				]),
				'riskTiers' => $l->t('From %1$s points, the count limits of the login, share and password reset checks are multiplied by %2$s, never below %3$s. From %4$s points, they are multiplied by %5$s, and every password login from the address needs extra confirmation.', [
					(string)RiskAssessment::SCORE_ELEVATED,
					(string)RiskAssessment::FACTOR_ELEVATED,
					(string)RiskAssessment::FLOOR,
					(string)RiskAssessment::SCORE_HIGH,
					(string)RiskAssessment::FACTOR_HIGH,
				]),
			],
		];
	}

	/**
	 * The labels of the choices of global settings that are no mode or severity.
	 *
	 * @return array<string, string>
	 */
	private function choiceLabels(IL10N $l): array {
		$labels = [
			'never' => $l->t('Never'),
			'daily' => $l->t('Daily'),
			'weekly' => $l->t('Weekly'),
		];
		foreach (NoMethodOutcome::cases() as $outcome) {
			$labels[$outcome->value] = $outcome->label($l);
		}
		return $labels;
	}

	/**
	 * @return array{0: ParamText, 1: string}
	 */
	private function describe(string $name, IL10N $l): array {
		foreach (StepUpPolicy::cases() as $policy) {
			if ($name === $policy->settingKey()) {
				return [new ParamText(
					$l->t('Nothing can confirm it: %s', [$policy->label($l)]),
					$l->t('What happens when such a login needs extra confirmation but nothing can confirm it. Default: %1$s. %2$s', [$policy->defaultOutcome()->label($l), $policy->defaultWhy($l)]),
				), self::GROUP_STEP_UP];
			}
		}
		return match ($name) {
			GlobalSettings::ENABLED => [new ParamText(
				$l->t('Intrusion detection'),
				$l->t('When it is off, no check runs, nothing is recorded and existing blocks are not enforced.'),
			), self::GROUP_MASTER],
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
				$l->t('Addresses from which this many different people whose accounts are at least 3 days old logged in successfully in the last 24 hours are not blocked. 0 turns this safety valve off.'),
				$l->t('people'),
			), self::GROUP_BLOCKS],
			GlobalSettings::RETENTION_DETECTIONS_DAYS => [new ParamText(
				$l->t('Keep records for'),
				$l->t('Older detections, logins and security changes of accounts (email address, password, second factor, app passwords) are deleted. A shorter period applies only after %s, so that lowering it cannot delete what happened before anyone saw the alert about the change. Blocks are kept 30 days after they end, for escalation.', [TextRenderer::duration(PurgeRetention::DELAY, $l)]),
				$l->t('days'),
			), self::GROUP_PRIVACY],
			GlobalSettings::EXPORT_FORMATS => [new ParamText(
				$l->t('Firewall export formats'),
				$l->t('The files written for your firewall or fail2ban. bans.log gets a line at once for every block; the other files are rewritten by the background job after a block changes, as often as cron runs (at most once a minute). They are only written when an export directory is set in config.php.'),
			), self::GROUP_EXPORT],
			GlobalSettings::NOTIFY_ADMIN_GROUP => [new ParamText(
				$l->t('Notify these groups'),
				$l->t('Members of these groups get the administrator notifications.'),
			), self::GROUP_NOTIFICATIONS],
			GlobalSettings::NOTIFY_ADMIN_EMAIL_MIN_SEVERITY => [new ParamText(
				$l->t('Also email from severity'),
				$l->t('Detections of this severity or higher are also emailed, at most once per check and hour. "never" sends no emails.'),
			), self::GROUP_NOTIFICATIONS],
			GlobalSettings::ADMIN_CHANGE_REQUIRE_APPROVAL => [new ParamText(
				$l->t('A second administrator approves new administrators'),
				$l->t('Someone added to the admin group through the web interface or the API is taken out again until another administrator approves. A request nobody approves within %s is dropped, and the requester is told. occ and directory-backed groups are not held back, only reported. Needs at least two administrators.', [TextRenderer::duration(ApprovalService::TTL, $l)]),
			), self::GROUP_APPROVALS],
			GlobalSettings::DIGEST_FREQUENCY => [new ParamText(
				$l->t('Send the digest'),
				$l->t('A summary of what intrusion detection saw and did, for everyone in the notification groups who has an email address. Weekly digests are sent on Monday at 08:00, daily ones every day at 08:00, in the server\'s time zone.'),
			), self::GROUP_NOTIFICATIONS],
			GlobalSettings::EVENTS_INCLUDE_IP => [new ParamText(
				$l->t('Addresses in webhook events'),
				$l->t('Whether the events sent to webhooks contain the attacking address. Turn this off when the receiving system must not get personal data.'),
			), self::GROUP_NOTIFICATIONS],
			GlobalSettings::STEP_UP_KNOWN_DEVICE_OK_FOR => [new ParamText(
				$l->t('Remembered devices confirm these logins'),
				$l->t('The reasons for which a browser the user chose to remember confirms a login without asking. A device never confirms a login whose password is being tried by attackers or is known from a breach, nor an administrator\'s login from outside the trusted networks.'),
			), self::GROUP_STEP_UP],
			GlobalSettings::STEP_UP_ADMIN_APPROVAL => [new ParamText(
				$l->t('An administrator can approve logins'),
				$l->t('When nothing else can confirm a login, it waits until an administrator approves it from the notification or this page. The account itself can never approve its own login.'),
			), self::GROUP_STEP_UP],
			GlobalSettings::KNOWN_DEVICE_ENABLED => [new ParamText(
				$l->t('Offer "Remember this device"'),
				$l->t('After confirming a login with a code or an administrator\'s approval, users may remember the browser, so that later logins from it are confirmed without asking.'),
			), self::GROUP_STEP_UP],
			GlobalSettings::RISK_ENABLED => [new ParamText(
				$l->t('Use the risk score'),
				$l->t('When it is off, every check uses its plain limits, and a high score never asks for confirmation.'),
			), self::GROUP_RISK],
			GlobalSettings::RISKY_NETWORK_OFFICE_NETWORKS => [new ParamText(
				$l->t('Trusted networks (office, VPN)'),
				$l->t('Your own networks and VPN, as addresses or ranges such as 203.0.113.0/24. Logins from them never count as risky, they lower the risk score, and administrators may log in from them when "Administrators log in from trusted networks only" is on.'),
			), self::GROUP_RISKY_NETWORK],
			GlobalSettings::ADMIN_TRUSTED_NETWORKS_ONLY => [new ParamText(
				$l->t('Administrators log in from trusted networks only'),
				$l->t('A password login of an administrator (the admin group or delegated administration) from outside the trusted networks must be confirmed with a second factor, an email code or, when it is on, another administrator\'s approval; a remembered device is not enough. Apps that send the password cannot confirm, so they are refused. For an account without any way to confirm, your choice for risky logins that cannot be confirmed decides. Apps with app passwords are not affected. Locked out? Run "occ config:app:set intrusion_detection admin_trusted_networks_only --value=false" on the server.'),
			), self::GROUP_STEP_UP],
			GlobalSettings::RISKY_NETWORK_EXEMPT_GROUPS => [new ParamText(
				$l->t('Exempt groups'),
				$l->t('Members of these groups may log in from hosting and Tor networks without extra confirmation, for example service accounts.'),
			), self::GROUP_RISKY_NETWORK],
			GlobalSettings::PERSONAL_PAGE_ENABLED => [new ParamText(
				$l->t('Show users their security events'),
				$l->t('Users see their security events, failed logins, recent logins, remembered devices and trusted networks in their own security settings, and can answer "Was this you?" there. When this is off, that part is hidden; notifications still reach them.'),
			), self::GROUP_PRIVACY],
			GlobalSettings::STALE_CREDENTIALS_REMOVE_DAYS => [new ParamText(
				$l->t('Remove app passwords and devices unused for'),
				$l->t('Once a day, app passwords and remembered browser logins that have not been used for this many days are removed, and each user is told once what was removed. 0 keeps them; otherwise at least %1$s days. Users are reminded, at most once a month, of those unused for %2$s days that are not removed yet.', [(string)GlobalSettings::STALE_CREDENTIALS_MIN_REMOVE_DAYS, (string)StaleCredentials::DAYS]),
				$l->t('days'),
			), self::GROUP_PRIVACY],
			default => [new ParamText(ucfirst(str_replace('_', ' ', $name))), self::GROUP_OTHER],
		};
	}
}
