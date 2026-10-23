<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

use OCA\IntrusionDetection\AdminChange\Approvers;
use OCA\IntrusionDetection\AdminChange\DelegatedGroups;
use OCP\IGroupManager;
use OCP\IUser;

/**
 * Who counts as an administrator for logins: the members of the admin
 * group and of groups with delegated administration settings
 * ({@see DelegatedGroups}). Core's cached group memberships, and when the
 * account is not in the admin group, the delegations (one query).
 */
class Administrators {
	public function __construct(
		private readonly IGroupManager $groupManager,
		private readonly DelegatedGroups $delegated,
	) {
	}

	public function isAdministrator(IUser $user): bool {
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
