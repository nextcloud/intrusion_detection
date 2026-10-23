<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

/**
 * Where the confirmation of a session's login stands; see {@see LoginConfirmation}.
 * The first four are also the statuses a step-up keeps in the session
 * ({@see StepUpState}).
 */
enum ConfirmationStatus: string {
	/** The login waits for its confirmation */
	case Pending = 'pending';
	/** Nothing could confirm the login: it was refused */
	case Refused = 'refused';
	/** An app or script logged in with the password: refused for this session */
	case RefusedClient = 'refused_client';
	/** A session whose login was never confirmed came back without its state: it is ended */
	case Resumed = 'resumed';
	/** The login needed a confirmation and got it, with a method */
	case Confirmed = 'confirmed';
	/** The login needed a confirmation and was let in without one, as the policies say */
	case AllowedUnconfirmed = 'allowed';
	/** The login needed nothing, and proved more than the password anyway: a second factor or a known device */
	case Proven = 'proven';
	/** The login needed nothing, or nothing is known about it */
	case None = 'none';

	/**
	 * Whether the session still has a step-up: it waits, was refused, or
	 * came back unconfirmed.
	 */
	public function isStepUp(): bool {
		return match ($this) {
			self::Pending, self::Refused, self::RefusedClient, self::Resumed => true,
			default => false,
		};
	}
}
