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
use OCA\IntrusionDetection\Controller\NoticeController;
use OCA\IntrusionDetection\Controller\PasswordChangeController;
use OCA\IntrusionDetection\Controller\VerifyController;
use OCA\IntrusionDetection\SessionState\ISessionStateRule;
use OCA\IntrusionDetection\SessionState\RequestTarget;
use OCA\IntrusionDetection\SessionState\SessionBlock;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCP\Authentication\TwoFactorAuth\ALoginSetupController;
use OCP\IRequest;
use OCP\IURLGenerator;

/**
 * Shows the security notice of users Nextcloud cannot reach by email
 * ({@see \OCA\IntrusionDetection\Notification\LoginNotices}) before the
 * start page: the first page a browser opens in a marked session is the
 * notice. Only page navigations are sent there; scripts, apps and WebDAV
 * are never blocked by it. With no notice this costs one session lookup.
 */
class LoginNoticeRule implements ISessionStateRule {
	public const ROUTE = Application::APP_ID . '.Notice.show';

	public function __construct(
		private readonly IRequest $request,
		private readonly IURLGenerator $urlGenerator,
	) {
	}

	#[\Override]
	public function check(SessionState $state, RequestTarget $target): ?SessionBlock {
		if (!isset($state->all()[SessionState::LOGIN_NOTICE]) || $target->dav || !$this->isPageNavigation($target)) {
			return null;
		}
		if ($target->isPublicPage()
			|| $target->isController(NoticeController::class)
			|| $target->isController(VerifyController::class)
			|| $target->isController(PasswordChangeController::class)
			|| $target->isController(TwoFactorChallengeController::class)
			|| $target->isController(ALoginSetupController::class)
			|| $target->isController(LoginController::class, 'logout')) {
			return null;
		}
		return new SessionBlock(
			'security_notice',
			'X-Nextcloud-Security-Notice',
			'There is a security notice for this account. Open Nextcloud in a browser to read it.',
			$this->urlGenerator->linkToRoute(self::ROUTE, ['redirect_url' => $target->uri]),
		);
	}

	private function isPageNavigation(RequestTarget $target): bool {
		return $target->isReadOnly()
			&& stripos($this->request->getHeader('Accept'), 'html') !== false
			&& $this->request->getHeader('OCS-APIREQUEST') === '';
	}
}
