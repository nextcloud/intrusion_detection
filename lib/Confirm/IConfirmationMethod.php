<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

use OCP\IUser;

/**
 * One way to confirm that a login is really the account holder's (concept
 * section 11.5). The methods are tried in the order of
 * {@see ConfirmationPolicy::METHODS}; the first that is available for the
 * account and every policy of the login is started at login.
 */
interface IConfirmationMethod {
	public const SECOND_FACTOR = 'second_factor';
	public const EMAIL_CODE = 'email_code';
	public const KNOWN_DEVICE = 'known_device';
	public const ADMIN_APPROVAL = 'admin_approval';

	/** The method confirmed the login by itself, or core confirms it next */
	public const CONFIRMED = 'confirmed';
	/** The user must confirm on the verify page */
	public const PENDING = 'pending';
	/** It could not be started (e.g. the email could not be sent): try the next method */
	public const UNAVAILABLE = 'unavailable';

	/**
	 * Stored in the session and the login's records; [a-z_] only.
	 */
	public function id(): string;

	/**
	 * Whether the method can confirm this account's login for this policy.
	 * Must be cheap: it runs at every login that needs confirmation. A
	 * method must never be weaker than the risk, so a policy can refuse a
	 * method (e.g. a known device does not prove who knows the password).
	 */
	public function isAvailable(IUser $user, StepUpPolicy $policy): bool;

	/**
	 * Whether the account could confirm a login with this policy at the
	 * login form, from any of its browsers. While it could, apps that send
	 * the password are refused: the account holder has a way in that proves
	 * more, and the app can use an app password. Must be cheap.
	 */
	public function isAvailableInBrowser(IUser $user, StepUpPolicy $policy): bool;

	/**
	 * Start confirming a login with this method. The method may keep what
	 * it needs in the state it returns, never a secret in plain text.
	 */
	public function begin(IUser $user, StepUpState $state): MethodStart;
}
