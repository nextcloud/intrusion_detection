<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SessionState;

/**
 * The pages a login passes through before it reaches Nextcloud, which the
 * session rules let through while they hold a session
 * ({@see RequestTarget::route()}).
 */
enum LoginFlowRoute {
	/** The app's verify page and its actions */
	case Verify;
	/** The app's page to choose a new password */
	case PasswordChange;
	/** The app's security notice before the start page */
	case Notice;
	/** Core's second-factor challenge */
	case SecondFactorChallenge;
	/** A provider's page to set up a second factor at login */
	case SecondFactorSetup;
	/** Logging out */
	case Logout;
}
