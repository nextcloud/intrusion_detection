<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm\Methods;

use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Confirm\IConfirmationMethod;
use OCA\IntrusionDetection\Confirm\MethodStart;
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
 * safe: see {@see StepUpPolicy::knownDeviceMayConfirm()}.
 */
class KnownDeviceMethod implements IConfirmationMethod {
	public function __construct(
		private readonly KnownDevices $devices,
		private readonly AppSettings $settings,
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
	public function begin(IUser $user, StepUpState $state): MethodStart {
		$device = $this->devices->recognise($user->getUID());
		if ($device === null) {
			return new MethodStart(self::UNAVAILABLE, $state);
		}
		$this->devices->used($device);
		return new MethodStart(self::CONFIRMED, $state);
	}

	/**
	 * Whether a known device may confirm a login with this policy at all.
	 */
	public function accepts(StepUpPolicy $policy): bool {
		return $policy->knownDeviceMayConfirm() && in_array($policy->value, $this->settings->stepUpKnownDeviceOkFor(), true);
	}
}
