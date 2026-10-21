<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Traps;

use OCP\IUserManager;

/**
 * Whether a login name belongs to an account, the way core resolves login
 * names: directly, or through the login name mapping of user backends.
 */
class AccountNames {
	public function __construct(
		private readonly IUserManager $userManager,
	) {
	}

	public static function normalise(string $name): string {
		return mb_strtolower(trim($name));
	}

	public function exists(string $name): bool {
		if ($name === '') {
			return false;
		}
		if ($this->userManager->userExists($name)) {
			return true;
		}
		$mapped = $this->userManager->getUserNameFromLoginName($name);
		return $mapped !== $name && $this->userManager->userExists($mapped);
	}
}
