<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

use OCA\IntrusionDetection\Notification\MailReach;
use OCP\IUser;

/**
 * What an account itself can confirm a login with, whatever the reason:
 * an email code, or its second factor. The confirmation methods, the
 * coverage report and the personal page ask here, so that they agree with
 * what a login accepts. A remembered device and an administrator's
 * approval are not the account's own: their methods decide them.
 */
class AccountMethods {
	public function __construct(
		private readonly MailReach $reach,
		private readonly SecondFactors $secondFactors,
	) {
	}

	/**
	 * A code can be sent: the account has a valid email address, and the
	 * server sends mail.
	 */
	public function byEmail(IUser $user): bool {
		return $this->reach->canReach($user);
	}

	/**
	 * A second factor that confirms logins is set up ({@see SecondFactors::trusted()}).
	 */
	public function bySecondFactor(IUser $user): bool {
		return $this->secondFactors->trusted($user);
	}

	/**
	 * Whether the account has any way of its own to confirm a login.
	 */
	public function any(IUser $user): bool {
		return $this->byEmail($user) || $this->bySecondFactor($user);
	}
}
