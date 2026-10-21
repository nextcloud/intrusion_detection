<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

use OC\Authentication\TwoFactorAuth\Manager;
use OCP\IUser;

/**
 * Whether core holds the current session at the setup of a second factor:
 * two factors are enforced for the account, it has none yet, and the login
 * must set one up before it continues. Only then does core let a login
 * reach the setup pages of the providers (`ALoginSetupController`), and
 * only then may a login that waits for its extra confirmation reach them.
 * The same test as core's two-factor middleware.
 */
class SecondFactorSetup {
	public function __construct(
		private readonly Manager $manager,
	) {
	}

	public function isRequired(IUser $user): bool {
		if (!$this->manager->needsSecondFactor($user)) {
			return false;
		}
		$providers = $this->manager->getProviderSet($user);
		return $providers->getPrimaryProviders() === [] && !$providers->isProviderMissing();
	}
}
