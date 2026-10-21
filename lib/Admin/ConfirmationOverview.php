<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Admin;

use OCA\IntrusionDetection\AdminChange\ApprovalService;
use OCA\IntrusionDetection\AdminChange\Approvers;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Prerequisites;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Confirm\ConfirmationCoverage;
use OCA\IntrusionDetection\Confirm\IConfirmationMethod;
use OCA\IntrusionDetection\Confirm\Methods\KnownDeviceMethod;
use OCA\IntrusionDetection\Confirm\NoMethodOutcome;
use OCA\IntrusionDetection\Confirm\StepUpReasons;
use OCA\IntrusionDetection\Db\Approval;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\IL10N;
use OCP\IUserManager;

/**
 * The Confirmation tab (concept sections 11.5 and 16.2): how Nextcloud
 * confirms that a risky login is really the account holder's, in the order
 * of {@see \OCA\IntrusionDetection\Confirm\ConfirmationPolicy::METHODS}; per reason, whether a remembered device counts
 * and what happens when nothing can confirm; how many accounts have no way
 * to confirm; and the logins that wait for an administrator.
 *
 * @psalm-import-type IntrusionDetectionConfirmation from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionConfirmationMethod from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionLoginApproval from ResponseDefinitions
 */
class ConfirmationOverview {
	/** At most this many waiting logins are listed */
	public const MAX_APPROVALS = 50;

	public function __construct(
		private readonly Settings $settings,
		private readonly Prerequisites $prerequisites,
		private readonly ConfirmationCoverage $coverage,
		private readonly Approvers $approvers,
		private readonly ApprovalService $approvals,
		private readonly IUserManager $userManager,
	) {
	}

	/**
	 * @return IntrusionDetectionConfirmation
	 */
	public function get(IL10N $l, string $viewer): array {
		$users = $this->coverage->users();
		$admins = $this->coverage->admins();
		return [
			'methods' => $this->methods($l),
			'policies' => $this->policies($l),
			'outcomes' => array_map(static fn (NoMethodOutcome $o): array => ['id' => $o->value, 'label' => $o->label($l), 'description' => $o->description($l)], NoMethodOutcome::cases()),
			'users' => ['withoutMethod' => $users['withoutMethod'], 'active' => $users['active']],
			'admins' => [
				'total' => $admins['total'],
				'withoutEmail' => count($admins['withoutEmail']),
				'withoutSecondFactor' => count($admins['withoutSecondFactor']),
				'withNeither' => $admins['withNeither'],
			],
			'approvers' => count($this->approvers->all()),
			'approvals' => $this->pendingLogins($viewer),
		];
	}

	/**
	 * @return list<IntrusionDetectionLoginApproval> the logins that wait for an administrator, oldest first
	 */
	public function pendingLogins(string $viewer): array {
		$list = [];
		foreach (array_reverse($this->approvals->list(true, self::MAX_APPROVALS, Approval::KIND_LOGIN)) as $approval) {
			$uid = $approval->getSubjectUid();
			$list[] = [
				'id' => (int)$approval->getId(),
				'uid' => $uid,
				'displayName' => $this->userManager->getDisplayName($uid) ?? $uid,
				'ip' => $approval->getIp(),
				'createdAt' => $approval->getCreatedAt(),
				'expiresAt' => $approval->getExpiresAt(),
				'canDecide' => $uid !== $viewer,
			];
		}
		return $list;
	}

	/**
	 * @return list<IntrusionDetectionConfirmationMethod>
	 */
	private function methods(IL10N $l): array {
		$methods = [];
		$approvers = count($this->approvers->all());
		$approvalOn = $this->settings->getBool(GlobalSettings::STEP_UP_ADMIN_APPROVAL);
		$methods[] = [
			'id' => IConfirmationMethod::SECOND_FACTOR,
			'name' => $l->t('Second factor'),
			'description' => $l->t('Accounts with two-factor authentication confirm with it. At a login through the login form, the second factor Nextcloud asks for anyway is the confirmation, so these users notice nothing extra.'),
			'state' => 'on',
			'note' => null,
		];
		$methods[] = [
			'id' => IConfirmationMethod::KNOWN_DEVICE,
			'name' => $l->t('Remembered device'),
			'description' => $l->t('After confirming a login, users may tick "Remember this device". Later logins from that browser are confirmed silently, because an attacker with only the password does not have it. It never counts when the password itself is at risk.'),
			'state' => $this->settings->getBool(GlobalSettings::KNOWN_DEVICE_ENABLED) ? 'on' : 'off',
			'note' => null,
		];
		$methods[] = [
			'id' => IConfirmationMethod::EMAIL_CODE,
			'name' => $l->t('Code by email'),
			'description' => $l->t('A 6-digit code is sent to the account\'s email address and must be entered on the confirmation page. Accounts without an email address never get one.'),
			'state' => $this->prerequisites->hasMail() ? 'on' : 'unavailable',
			'note' => $this->prerequisites->hasMail() ? null : $l->t('Nextcloud cannot send emails, so this method is skipped. Set up email in the basic settings.'),
		];
		$methods[] = [
			'id' => IConfirmationMethod::ADMIN_APPROVAL,
			'name' => $l->t('Administrator approval'),
			'description' => $l->t('The login waits on a page that continues by itself once an administrator approves it from the notification or this tab. Nobody can approve their own login.'),
			'state' => !$approvalOn ? 'off' : ($approvers === 0 ? 'unavailable' : 'on'),
			'note' => $approvalOn && $approvers < 2 ? $l->t('With only one administrator, that administrator\'s own logins can never be approved.') : null,
		];
		return $methods;
	}

	/**
	 * @return list<array{id: string, label: string, why: string, default: string, outcome: string, setting: string, knownDevice: bool, knownDeviceAllowed: bool}>
	 */
	private function policies(IL10N $l): array {
		$knownDeviceOk = $this->settings->global(GlobalSettings::STEP_UP_KNOWN_DEVICE_OK_FOR);
		$knownDeviceOk = is_array($knownDeviceOk) ? $knownDeviceOk : [];
		$policies = [];
		foreach (StepUpReasons::policies() as $policy) {
			$outcome = NoMethodOutcome::tryFrom((string)$this->settings->global($policy->settingKey())) ?? $policy->defaultOutcome();
			$allowed = !in_array($policy, KnownDeviceMethod::NEVER, true);
			$policies[] = [
				'id' => $policy->value,
				'label' => $policy->label($l),
				'why' => $policy->defaultWhy($l),
				'default' => $policy->defaultOutcome()->value,
				'outcome' => $outcome->value,
				'setting' => $policy->settingKey(),
				'knownDevice' => $allowed && in_array($policy->value, $knownDeviceOk, true),
				'knownDeviceAllowed' => $allowed,
			];
		}
		return $policies;
	}
}
