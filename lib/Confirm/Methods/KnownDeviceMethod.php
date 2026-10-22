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
 * safe, nor where the login comes from. So it never confirms a login whose
 * password is being sprayed or is known from a breach, nor an
 * administrator's login from outside the trusted networks (NEVER), and the
 * other policies accept it only as `step_up_known_device_ok_for` says.
 */
class KnownDeviceMethod implements IConfirmationMethod {
	/** @var list<StepUpPolicy> */
	public const NEVER = [StepUpPolicy::SprayedPassword, StepUpPolicy::BreachedPassword, StepUpPolicy::AdminOutsideNetworks];
	/** @var list<string> */
	public const DEFAULT_POLICIES = ['flagged_source', 'protected_account', 'risky_network', 'risk_high'];
	/** The policies the setting may name: every one but NEVER */
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

	/**
	 * Any of the account's remembered devices, not only the current request's.
	 */
	#[\Override]
	public function isAvailableInBrowser(IUser $user, StepUpPolicy $policy): bool {
		return $this->accepts($policy) && $this->devices->hasDevices($user->getUID());
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
		if (in_array($policy, self::NEVER, true)) {
			return false;
		}
		$allowed = $this->settings->global(GlobalSettings::STEP_UP_KNOWN_DEVICE_OK_FOR);
		return is_array($allowed) && in_array($policy->value, $allowed, true);
	}
}
