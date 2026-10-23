<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Controller;

use OC\User\Session;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Http\LocalRedirect;
use OCA\IntrusionDetection\Login\SessionMarkers;
use OCA\IntrusionDetection\Response\PasswordChangeService;
use OCA\IntrusionDetection\SessionState\ILoginFlowPage;
use OCA\IntrusionDetection\SessionState\LoginFlowRoute;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\BruteForceProtection;
use OCP\AppFramework\Http\Attribute\FrontpageRoute;
use OCP\AppFramework\Http\Attribute\NoAdminRequired;
use OCP\AppFramework\Http\Attribute\NoCSRFRequired;
use OCP\AppFramework\Http\Attribute\OpenAPI;
use OCP\AppFramework\Http\Attribute\UserRateLimit;
use OCP\AppFramework\Http\Attribute\UseSession;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\Http\Response;
use OCP\AppFramework\Http\StandaloneTemplateResponse;
use OCP\HintException;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\IUserManager;
use OCP\IUserSession;
use OCP\Util;

/**
 * The page that asks for a new password when one is required (concept
 * section 11.7): the current password, the new one twice. The new password
 * is set with {@see IUser::setPassword()}, so the password policy applies
 * and its message is shown.
 *
 * The page needs a finished login, second factor included: otherwise
 * whoever knows only the password could choose the new one. It is
 * CSRF-protected, rate limited per user, and wrong current passwords are
 * throttled like failed logins. Passwords are never logged or kept.
 */
#[OpenAPI(scope: OpenAPI::SCOPE_IGNORE)]
class PasswordChangeController extends Controller implements ILoginFlowPage {
	public const TEMPLATE = 'password';
	public const BRUTE_FORCE_ACTION = 'intrusion_detection_password';
	/** Never continued to: this page itself */
	private const EXCLUDED = ['/apps/' . Application::APP_ID . '/password'];

	public function __construct(
		IRequest $request,
		private readonly IUserSession $userSession,
		private readonly IUserManager $userManager,
		private readonly PasswordChangeService $passwords,
		private readonly SessionMarkers $state,
		private readonly IURLGenerator $urlGenerator,
		private readonly IL10N $l,
		private readonly LocalRedirect $redirect,
	) {
		parent::__construct(Application::APP_ID, $request);
	}

	#[\Override]
	public static function loginFlowRoute(): LoginFlowRoute {
		return LoginFlowRoute::PasswordChange;
	}

	#[NoAdminRequired]
	#[NoCSRFRequired]
	#[UseSession]
	#[FrontpageRoute(verb: 'GET', url: '/password')]
	public function show(string $redirect_url = ''): Response {
		$user = $this->userSession->getUser();
		if ($user === null || !$this->stillRequired($user)) {
			return new RedirectResponse($this->target($redirect_url));
		}
		return $this->page($redirect_url);
	}

	#[NoAdminRequired]
	#[UseSession]
	#[UserRateLimit(limit: 10, period: 600)]
	#[BruteForceProtection(action: self::BRUTE_FORCE_ACTION)]
	#[FrontpageRoute(verb: 'POST', url: '/password')]
	public function change(
		#[\SensitiveParameter]
		string $currentPassword = '',
		#[\SensitiveParameter]
		string $newPassword = '',
		#[\SensitiveParameter]
		string $newPasswordRepeat = '',
		string $redirect_url = '',
	): Response {
		$user = $this->userSession->getUser();
		if ($user === null || !$this->stillRequired($user)) {
			return new RedirectResponse($this->target($redirect_url));
		}
		if (!$this->isCurrentPassword($user, $currentPassword)) {
			$response = $this->page($redirect_url, $this->l->t('Your current password is not correct.'), Http::STATUS_FORBIDDEN);
			$response->throttle();
			return $response;
		}
		if ($newPassword === '') {
			return $this->page($redirect_url, $this->l->t('Enter a new password.'));
		}
		if (!hash_equals($newPassword, $newPasswordRepeat)) {
			return $this->page($redirect_url, $this->l->t('The two new passwords are not the same. Type the new password twice.'));
		}
		if (hash_equals($currentPassword, $newPassword)) {
			return $this->page($redirect_url, $this->l->t('Choose a password that is different from your current one.'));
		}
		if (strlen($newPassword) > IUserManager::MAX_PASSWORD_LENGTH) {
			return $this->page($redirect_url, $this->l->t('The new password is too long.'));
		}
		try {
			if (!$user->setPassword($newPassword)) {
				return $this->page($redirect_url, $this->l->t('Your password could not be changed. Try again, or contact your administrator.'));
			}
		} catch (HintException $e) {
			return $this->page($redirect_url, $e->getHint());
		}
		if ($this->userSession instanceof Session) {
			// Keeps this browser session valid with the new password, as the personal settings do.
			$this->userSession->updateSessionTokenPassword($newPassword);
		}
		$this->passwords->clear($user->getUID(), 'password changed on the password page');
		$this->state->remove(SessionMarkers::PASSWORD_CHANGE);
		return new RedirectResponse($this->target($redirect_url));
	}

	/**
	 * Whether this account must still choose a password here. Only reads:
	 * the session rule drops a stale marker
	 * ({@see \OCA\IntrusionDetection\SessionState\Rules\PasswordChangeRule}).
	 */
	private function stillRequired(IUser $user): bool {
		return $this->passwords->isRequired($user->getUID()) && $user->canChangePassword();
	}

	/**
	 * Checked with the login name of the session, as the personal settings
	 * do, because directories such as LDAP check passwords by login name.
	 */
	private function isCurrentPassword(IUser $user, #[\SensitiveParameter] string $password): bool {
		if ($password === '') {
			return false;
		}
		$loginName = $this->userSession instanceof Session ? $this->userSession->getLoginName() : null;
		$checked = $this->userManager->checkPassword(is_string($loginName) && $loginName !== '' ? $loginName : $user->getUID(), $password);
		return $checked !== false && $checked->getUID() === $user->getUID();
	}

	private function page(string $redirectUrl, ?string $error = null, int $status = Http::STATUS_OK): StandaloneTemplateResponse {
		Util::addStyle(Application::APP_ID, 'pages');
		$response = new StandaloneTemplateResponse(Application::APP_ID, self::TEMPLATE, [
			'action' => $this->urlGenerator->linkToRoute(Application::APP_ID . '.PasswordChange.change'),
			'redirect_url' => LocalRedirect::isSafe($redirectUrl, self::EXCLUDED) ? $redirectUrl : '',
			'logout_url' => $this->urlGenerator->getLogoutUrl(),
			'error' => $error,
		], 'guest');
		$response->setStatus($error === null ? Http::STATUS_OK : ($status === Http::STATUS_OK ? Http::STATUS_BAD_REQUEST : $status));
		return $response;
	}

	private function target(string $redirectUrl): string {
		return $this->redirect->target($redirectUrl, self::EXCLUDED);
	}
}
