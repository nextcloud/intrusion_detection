<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\AdminChange;

use OCP\IGroupManager;
use OCP\IUser;
use OCP\IUserManager;

/**
 * The administrators who can decide on a request: the enabled members of the
 * admin group. Delegated administrators and group administrators cannot.
 */
class Approvers {
	public const ADMIN_GROUP = 'admin';
	/** At most this many are read, so a huge group stays cheap */
	public const MAX = 100;

	public function __construct(
		private readonly IGroupManager $groupManager,
		private readonly IUserManager $userManager,
	) {
	}

	/**
	 * @return list<IUser>
	 */
	public function all(): array {
		$group = $this->groupManager->get(self::ADMIN_GROUP);
		if ($group === null) {
			return [];
		}
		$users = [];
		foreach ($group->searchUsers('', self::MAX) as $user) {
			if ($user->isEnabled()) {
				$users[$user->getUID()] = $user;
			}
		}
		return array_values($users);
	}

	public function count(): int {
		return count($this->all());
	}

	/**
	 * Whether an account is an enabled member of the admin group. Group
	 * membership is checked rather than IGroupManager::isAdmin(), which also
	 * depends on the address of the current request and so is not usable on
	 * the command line.
	 */
	public function isApprover(string $uid): bool {
		$user = $this->userManager->get($uid);
		return $user !== null && $user->isEnabled() && $this->groupManager->isInGroup($user->getUID(), self::ADMIN_GROUP);
	}

	/**
	 * @param list<string> $excluded uids that must not decide (the requester and the subject)
	 * @return list<IUser>
	 */
	public function except(array $excluded): array {
		return array_values(array_filter($this->all(), static fn (IUser $u): bool => !in_array($u->getUID(), $excluded, true)));
	}
}
