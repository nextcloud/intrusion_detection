<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SessionState\Rules;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Login\LoginKind;
use OCA\IntrusionDetection\Login\SessionMarkers;
use OCA\IntrusionDetection\Response\PasswordChangeFlag;
use OCA\IntrusionDetection\Response\PasswordChangeService;
use OCA\IntrusionDetection\SessionState\ISessionStateRule;
use OCA\IntrusionDetection\SessionState\LoginFlowRoute;
use OCA\IntrusionDetection\SessionState\RequestTarget;
use OCA\IntrusionDetection\SessionState\SessionBlock;
use OCP\IURLGenerator;
use OCP\IUserSession;
use Psr\Container\ContainerInterface;

/**
 * While a session must choose a new password (concept section 11.7), it can
 * reach nothing but the password page, logging out, the second-factor pages
 * of the login, the verify page of a login that still needs its extra
 * confirmation ({@see StepUpRule} comes first), and public read-only
 * resources such as styles. Browsers are sent to the password page;
 * everything else gets 403.
 *
 * The login listener marks the session. A marker whose requirement was
 * lifted meanwhile (password changed elsewhere, an admin cleared it) is
 * dropped, also on the password page; that check reads the database only
 * for marked sessions. An account whose password cannot be changed here
 * (a directory manages it) gets the administrators asked to reset it
 * there, and its marker dropped: the page itself never changes anything.
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
		private readonly ContainerInterface $container,
	) {
	}

	/**
	 * How a login of this kind is held while a new password is required:
	 * browsers are sent to the password page, apps and scripts with the
	 * password are refused, and app passwords and tokens are left alone
	 * (null): whoever guessed the password does not have them.
	 *
	 * @return self::MODE_*|null
	 */
	public static function modeFor(LoginKind $kind): ?string {
		return match ($kind) {
			LoginKind::ClientPassword => self::MODE_REFUSE,
			LoginKind::AppPasswordBasic, LoginKind::Bearer => null,
			default => self::MODE_REDIRECT,
		};
	}

	#[\Override]
	public function check(SessionMarkers $state, RequestTarget $target): ?SessionBlock {
		$marker = $state->get(SessionMarkers::PASSWORD_CHANGE);
		if ($marker === null) {
			return null;
		}
		$user = $this->userSession->getUser();
		$uid = $user?->getUID();
		if ($user === null || $uid !== ($marker['uid'] ?? null) || !$this->flag->isRequired($uid)) {
			$state->remove(SessionMarkers::PASSWORD_CHANGE);
			return null;
		}
		if (!$user->canChangePassword()) {
			$this->container->get(PasswordChangeService::class)->external($user);
			$state->remove(SessionMarkers::PASSWORD_CHANGE);
			return null;
		}
		if (!$target->dav && self::isExempt($target)) {
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
		return $target->isRoute(
			LoginFlowRoute::PasswordChange,
			LoginFlowRoute::Verify,
			LoginFlowRoute::Logout,
			LoginFlowRoute::SecondFactorChallenge,
			LoginFlowRoute::SecondFactorSetup,
		) || $target->isPublicResource();
	}
}
