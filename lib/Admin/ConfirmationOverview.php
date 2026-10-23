<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Admin;

use OCA\IntrusionDetection\AdminChange\ApprovalService;
use OCA\IntrusionDetection\AdminChange\Approvers;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Config\Prerequisites;
use OCA\IntrusionDetection\Confirm\ConfirmationCoverage;
use OCA\IntrusionDetection\Confirm\IConfirmationMethod;
use OCA\IntrusionDetection\Confirm\Methods\KnownDeviceMethod;
use OCA\IntrusionDetection\Confirm\NoMethodOutcome;
use OCA\IntrusionDetection\Confirm\NoMethodPreset;
use OCA\IntrusionDetection\Confirm\StepUpReasons;
use OCA\IntrusionDetection\Confirm\UntrustedSecondFactors;
use OCA\IntrusionDetection\Db\Approval;
use OCA\IntrusionDetection\Explain\TextRenderer;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\IL10N;
use OCP\IUserManager;

/**
 * The Confirmation tab (concept sections 11.5 and 16.2): how Nextcloud
 * confirms that a risky login is really the account holder's, in the order
 * of {@see \OCA\IntrusionDetection\Confirm\ConfirmationPolicy::METHODS}; per reason, whether a remembered device counts
 * and what happens when nothing can confirm; how many accounts have no way
 * to confirm; and the logins that wait for an administrator, read on their
 * own ({@see pendingLogins()}). The outcomes
 * of all reasons together are one {@see NoMethodPreset}, or "custom".
 *
 * @psalm-import-type IntrusionDetectionConfirmation from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionConfirmationMethod from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionLoginApproval from ResponseDefinitions
 */
class ConfirmationOverview {
	/** At most this many waiting logins are listed */
	public const MAX_APPROVALS = 50;

	public function __construct(
		private readonly AppSettings $settings,
		private readonly Prerequisites $prerequisites,
		private readonly ConfirmationCoverage $coverage,
		private readonly Approvers $approvers,
		private readonly ApprovalService $approvals,
		private readonly IUserManager $userManager,
		private readonly NoMethodPreset $preset,
	) {
	}

	/**
	 * @return IntrusionDetectionConfirmation
	 */
	public function get(IL10N $l): array {
		$users = $this->coverage->users();
		$admins = $this->coverage->admins();
		return [
			'methods' => $this->methods($l),
			'policies' => $this->policies($l),
			'preset' => $this->preset->current(),
			'outcomes' => array_map(static fn (NoMethodOutcome $o): array => ['id' => $o->value, 'label' => $o->label($l), 'description' => $o->description($l)], NoMethodOutcome::cases()),
			'users' => ['withoutMethod' => $users['withoutMethod'], 'active' => $users['active']],
			'admins' => [
				'total' => $admins['total'],
				'withoutEmail' => count($admins['withoutEmail']),
				'withoutSecondFactor' => count($admins['withoutSecondFactor']),
				'withNeither' => $admins['withNeither'],
			],
			'approvers' => count($this->approvers->all()),
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
		$approvalOn = $this->settings->stepUpAdminApproval();
		$methods[] = [
			'id' => IConfirmationMethod::SECOND_FACTOR,
			'name' => $l->t('Second factor'),
			'description' => $l->t('Accounts with two-factor authentication confirm with it. At a login through the login form, the second factor Nextcloud asks for anyway is the confirmation, so these users notice nothing extra. A second factor added after a login that proved only the password counts after %1$s, or once it is set up again after a confirmed login; one added while a login waited for its confirmation or was let in without one counts only then.', [TextRenderer::duration(UntrustedSecondFactors::PASSWORD_DELAY, $l)]),
			'state' => 'on',
			'note' => null,
		];
		$methods[] = [
			'id' => IConfirmationMethod::KNOWN_DEVICE,
			'name' => $l->t('Remembered device'),
			'description' => $l->t('After confirming a login, users may tick "Remember this device". Later logins from that browser are confirmed silently, because an attacker with only the password does not have it. It never counts when the password itself is at risk.'),
			'state' => $this->settings->knownDeviceEnabled() ? 'on' : 'off',
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
	 * What each reason accepts, as stored.
	 *
	 * @return list<array{id: string, label: string, why: string, default: string, outcome: string, setting: string, knownDevice: bool, knownDeviceAllowed: bool}>
	 */
	public function policies(IL10N $l): array {
		$knownDeviceOk = $this->settings->stepUpKnownDeviceOkFor();
		$policies = [];
		foreach (StepUpReasons::policies() as $policy) {
			$outcome = NoMethodOutcome::tryFrom($this->settings->stepUpNoMethod($policy->value)) ?? $policy->defaultOutcome();
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
