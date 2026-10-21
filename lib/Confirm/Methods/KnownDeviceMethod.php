<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm\Methods;

use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Confirm\IConfirmationMethod;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCA\IntrusionDetection\KnownDevice\KnownDevices;
use OCP\IUser;

/**
 * The browser is one the user remembered after an earlier confirmed login
 * (concept section 11.5.1): possession of that device is something an
 * attacker with just the password does not have. It confirms the login
 * silently, without asking anything.
 *
 * A device proves who holds the device, not that the password is still
 * safe. So it never confirms a login whose password is being sprayed or is
 * known from a breach, nor a sensitive action in a risky session, which
 * runs on that very device (NEVER). A login during lockdown accepts it only
 * when `lockdown_known_device_ok` is on, and the other policies only as
 * `step_up_known_device_ok_for` says.
 */
class KnownDeviceMethod implements IConfirmationMethod {
	/** @var list<StepUpPolicy> */
	public const NEVER = [StepUpPolicy::SprayedPassword, StepUpPolicy::BreachedPassword, StepUpPolicy::Lockdown, StepUpPolicy::SensitiveAction];
	/** @var list<string> */
	public const DEFAULT_POLICIES = ['flagged_source', 'protected_account', 'risky_network', 'risk_high'];
	/** The policies `step_up_known_device_ok_for` may name: every one but NEVER; lockdown has its own setting */
	public const POLICY_PATTERN = '/^(flagged_source|protected_account|risky_network|risk_high)$/';

	public function __construct(
		private readonly KnownDevices $devices,
		private readonly Settings $settings,
	) {
	}

	#[\Override]
	public function id(): string {
		return self::KNOWN_DEVICE;
	}

	#[\Override]
	public function isAvailable(IUser $user, StepUpPolicy $policy): bool {
		return $this->accepts($policy) && $this->devices->recognise($user->getUID()) !== null;
	}

	#[\Override]
	public function begin(IUser $user, StepUpState $state): string {
		$device = $this->devices->recognise($user->getUID());
		if ($device === null) {
			return self::UNAVAILABLE;
		}
		$this->devices->used($device);
		return self::CONFIRMED;
	}

	/**
	 * Whether a known device may confirm a login with this policy at all.
	 */
	public function accepts(StepUpPolicy $policy): bool {
		if ($policy === StepUpPolicy::Lockdown) {
			return $this->settings->getBool(GlobalSettings::LOCKDOWN_KNOWN_DEVICE_OK);
		}
		if (in_array($policy, self::NEVER, true)) {
			return false;
		}
		$allowed = $this->settings->global(GlobalSettings::STEP_UP_KNOWN_DEVICE_OK_FOR);
		return is_array($allowed) && in_array($policy->value, $allowed, true);
	}
}
