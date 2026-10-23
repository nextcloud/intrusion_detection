<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm\Reasons;

use OCA\IntrusionDetection\AdminChange\Approvers;
use OCA\IntrusionDetection\AdminChange\DelegatedGroups;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Confirm\IStepUpReason;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Login\LoginContext;
use OCA\IntrusionDetection\Net\RangeCodec;
use OCP\IGroupManager;
use OCP\IUser;

/**
 * An administrator logs in from outside the trusted networks
 * (`risky_network_office_networks`) while `admin_trusted_networks_only` is
 * on. Administrators are the members of the admin group and of groups with
 * delegated administration settings ({@see DelegatedGroups}). The networks
 * of a user's "Yes, it was me" do not count: the point is the network.
 *
 * Nothing is read while the switch is off; otherwise the cached network
 * list, and for an address outside it core's cached group memberships and,
 * when the account is not in the admin group, the delegations (one query).
 * It applies whatever the learning mode: the switch is an explicit rule,
 * not a detection. A login without a known address counts as outside.
 */
class AdminOutsideNetworksReason implements IStepUpReason {
	public function __construct(
		private readonly AppSettings $settings,
		private readonly IGroupManager $groupManager,
		private readonly DelegatedGroups $delegated,
	) {
	}

	#[\Override]
	public static function policy(): StepUpPolicy {
		return StepUpPolicy::AdminOutsideNetworks;
	}

	#[\Override]
	public function applies(LoginContext $login): bool {
		if (!$this->settings->adminTrustedNetworksOnly()) {
			return false;
		}
		if ($login->source !== null && RangeCodec::firstContaining($this->settings->riskyNetworkOfficeNetworks(), $login->source) !== null) {
			return false;
		}
		return $this->isAdministrator($login->user);
	}

	private function isAdministrator(IUser $user): bool {
		if ($this->groupManager->isInGroup($user->getUID(), Approvers::ADMIN_GROUP)) {
			return true;
		}
		$delegations = $this->delegated->all();
		if ($delegations === []) {
			return false;
		}
		foreach ($this->groupManager->getUserGroupIds($user) as $gid) {
			if (isset($delegations[$gid])) {
				return true;
			}
		}
		return false;
	}
}
