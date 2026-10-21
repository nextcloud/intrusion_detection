<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SessionState\Rules;

use OC\Core\Controller\LoginController;
use OC\Core\Controller\TwoFactorChallengeController;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Controller\PasswordChangeController;
use OCA\IntrusionDetection\Response\PasswordChangeFlag;
use OCA\IntrusionDetection\SessionState\ISessionStateRule;
use OCA\IntrusionDetection\SessionState\RequestTarget;
use OCA\IntrusionDetection\SessionState\SessionBlock;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCP\Authentication\TwoFactorAuth\ALoginSetupController;
use OCP\IURLGenerator;
use OCP\IUserSession;

/**
 * While a session must choose a new password (concept section 11.7), it can
 * reach nothing but the password page, logging out, the second-factor pages
 * of the login, and public read-only resources such as styles. Browsers are
 * sent to the password page; everything else gets 403.
 *
 * The login listener marks the session. A marker whose requirement was
 * lifted meanwhile (password changed elsewhere, an admin cleared it) is
 * dropped; that check reads the database only for marked sessions.
 */
class PasswordChangeRule implements ISessionStateRule {
	public const ERROR = 'password_change_required';
	public const DAV_HEADER = 'X-Nextcloud-Password-Change';
	/** Browser logins are sent to the password page */
	public const MODE_REDIRECT = 'redirect';
	/** Logins with the password from apps and scripts cannot open a page: refused */
	public const MODE_REFUSE = 'refuse';
	public const ROUTE = Application::APP_ID . '.PasswordChange.show';

	public function __construct(
		private readonly PasswordChangeFlag $flag,
		private readonly IUserSession $userSession,
		private readonly IURLGenerator $urlGenerator,
	) {
	}

	#[\Override]
	public function check(SessionState $state, RequestTarget $target): ?SessionBlock {
		$marker = $state->get(SessionState::PASSWORD_CHANGE);
		if ($marker === null || (!$target->dav && self::isExempt($target))) {
			return null;
		}
		$uid = $this->userSession->getUser()?->getUID();
		if ($uid === null || $uid !== ($marker['uid'] ?? null) || !$this->flag->isRequired($uid)) {
			$state->remove(SessionState::PASSWORD_CHANGE);
			return null;
		}
		$redirect = ($marker['mode'] ?? null) === self::MODE_REDIRECT
			? $this->urlGenerator->linkToRoute(self::ROUTE, ['redirect_url' => $target->uri])
			: null;
		return new SessionBlock(
			self::ERROR,
			self::DAV_HEADER,
			'A new password must be chosen before this account can be used again. Log in with a browser to choose one.',
			$redirect,
		);
	}

	public static function isExempt(RequestTarget $target): bool {
		return $target->isController(PasswordChangeController::class)
			|| $target->isController(LoginController::class, 'logout')
			|| $target->isController(TwoFactorChallengeController::class)
			|| $target->isController(ALoginSetupController::class)
			|| ($target->isReadOnly() && $target->isPublicPage());
	}
}
