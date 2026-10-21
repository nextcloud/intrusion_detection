<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Controller;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\StepUpFailed;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Confirm\ConfirmationPages;
use OCA\IntrusionDetection\Confirm\ConfirmationPolicy;
use OCA\IntrusionDetection\Confirm\EmailCodes;
use OCA\IntrusionDetection\Confirm\IConfirmationMethod;
use OCA\IntrusionDetection\Confirm\LoginConfirmationFlow;
use OCA\IntrusionDetection\Confirm\StepUpService;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCA\IntrusionDetection\Http\LocalRedirect;
use OCA\IntrusionDetection\KnownDevice\KnownDevices;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Sensitive\ActionConfirmationFlow;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\BruteForceProtection;
use OCP\AppFramework\Http\Attribute\FrontpageRoute;
use OCP\AppFramework\Http\Attribute\NoAdminRequired;
use OCP\AppFramework\Http\Attribute\NoCSRFRequired;
use OCP\AppFramework\Http\Attribute\OpenAPI;
use OCP\AppFramework\Http\Attribute\PublicPage;
use OCP\AppFramework\Http\Attribute\UserRateLimit;
use OCP\AppFramework\Http\Attribute\UseSession;
use OCP\AppFramework\Http\JSONResponse;
use OCP\AppFramework\Http\Response;
use OCP\AppFramework\Http\StandaloneTemplateResponse;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IURLGenerator;
use OCP\IUserSession;

/**
 * The verify page (concept sections 11.5 and 15.2): a login that needs
 * extra confirmation is held here until the code sent by email is entered
 * (or the second factor, where the account has one), or until an
 * administrator approved it. A refused login is told why, with a reference,
 * and ended. A login that could not be confirmed ends on a public page that
 * only says so.
 *
 * - After a correct code or an administrator's approval, the user may tick
 *   "Remember this device" ({@see KnownDevices}): later logins from this
 *   browser are confirmed without asking, where the reason allows it.
 * - While an administrator is asked, the page shows that it waits and asks
 *   a cheap status endpoint every few seconds (the verify script); without
 *   the script, "Check now" does the same. The user can give up waiting.
 *
 * There is no #[NoTwoFactorRequired]: an account with a second factor is
 * confirmed by core's challenge at login and never sent here, so a session
 * that still waits for its second factor goes to the challenge first. The
 * pages and their actions are shared with the confirmation of sensitive
 * actions ({@see ConfirmationPages}, {@see LoginConfirmationFlow}).
 */
#[OpenAPI(scope: OpenAPI::SCOPE_IGNORE)]
class VerifyController extends Controller {
	public const TEMPLATE = ConfirmationPages::TEMPLATE;
	public const BRUTE_FORCE_ACTION = ConfirmationPages::BRUTE_FORCE_ACTION;
	/** Never continued to: the verify pages themselves */
	public const EXCLUDED = LoginConfirmationFlow::EXCLUDED;
	public const MODE_CODE = ConfirmationPages::MODE_CODE;
	public const MODE_REFUSED = ConfirmationPages::MODE_REFUSED;
	public const MODE_ENDED = ConfirmationPages::MODE_ENDED;
	public const MODE_WAITING = ConfirmationPages::MODE_WAITING;
	public const POLL_INTERVAL = ConfirmationPages::POLL_INTERVAL;

	private readonly ConfirmationPages $pages;
	private readonly IUserSession $userSession;
	private readonly IURLGenerator $urlGenerator;
	private readonly IL10N $l;

	public function __construct(
		IRequest $request,
		IUserSession $userSession,
		private readonly StepUpService $stepUps,
		EmailCodes $codes,
		ConfirmationPolicy $policy,
		Settings $settings,
		IURLGenerator $urlGenerator,
		LocalRedirect $redirect,
		IL10N $l,
		KnownDevices $knownDevices,
		RemoteAddressResolver $addresses,
		ITimeFactory $timeFactory,
	) {
		parent::__construct(Application::APP_ID, $request);
		$this->userSession = $userSession;
		$this->urlGenerator = $urlGenerator;
		$this->l = $l;
		$flow = new LoginConfirmationFlow($stepUps, $knownDevices, $addresses, $request, $urlGenerator, $l);
		$this->pages = new ConfirmationPages($flow, $userSession, $codes, $policy, $settings, $urlGenerator, $redirect, $l, $knownDevices, $timeFactory);
	}

	#[NoAdminRequired]
	#[NoCSRFRequired]
	#[UseSession]
	#[FrontpageRoute(verb: 'GET', url: '/verify')]
	public function show(string $redirect_url = '', string $use = ''): Response {
		$user = $this->userSession->getUser();
		$stepUp = $this->stepUps->current();
		if ($user === null || $stepUp === null || $stepUp->uid !== $user->getUID()) {
			return $this->pages->continue($redirect_url);
		}
		if ($stepUp->status === StepUpState::REFUSED) {
			$response = $this->refusedPage($stepUp);
			$this->stepUps->endRefused();
			return $response;
		}
		if (!$stepUp->isPending()) {
			return $this->pages->continue($redirect_url);
		}
		if ($stepUp->approvalId !== null && !($use === self::MODE_CODE && $stepUp->hasMethod(IConfirmationMethod::EMAIL_CODE))) {
			return $this->pages->waitingPage($user, $stepUp, $redirect_url);
		}
		return $this->pages->codePage($user, $stepUp, $redirect_url);
	}

	#[NoAdminRequired]
	#[UseSession]
	#[UserRateLimit(limit: 20, period: 600)]
	#[BruteForceProtection(action: self::BRUTE_FORCE_ACTION)]
	#[FrontpageRoute(verb: 'POST', url: '/verify')]
	public function confirm(
		#[\SensitiveParameter]
		string $code = '',
		string $redirect_url = '',
		string $remember = '',
	): Response {
		return $this->pages->confirmCode($code, $redirect_url, $remember);
	}

	#[NoAdminRequired]
	#[UseSession]
	#[UserRateLimit(limit: 10, period: 600)]
	#[FrontpageRoute(verb: 'POST', url: '/verify/resend')]
	public function resend(string $redirect_url = ''): Response {
		return $this->pages->resendCode($redirect_url);
	}

	#[NoAdminRequired]
	#[UseSession]
	#[UserRateLimit(limit: 10, period: 600)]
	#[FrontpageRoute(verb: 'POST', url: '/verify/second-factor')]
	public function secondFactor(string $redirect_url = ''): Response {
		return $this->pages->askSecondFactor($redirect_url);
	}

	/**
	 * Ask an administrator to approve the login, instead of entering a code.
	 */
	#[NoAdminRequired]
	#[UseSession]
	#[UserRateLimit(limit: 5, period: 600)]
	#[FrontpageRoute(verb: 'POST', url: '/verify/approval')]
	public function requestApproval(string $redirect_url = ''): Response {
		return $this->pages->askAdministrator($redirect_url);
	}

	/**
	 * Whether an administrator decided on the waiting login: what the
	 * waiting page asks every few seconds.
	 */
	#[NoAdminRequired]
	#[NoCSRFRequired]
	#[UserRateLimit(limit: 120, period: 600)]
	#[FrontpageRoute(verb: 'GET', url: '/verify/approval/status')]
	public function approvalStatus(): JSONResponse {
		return $this->pages->approvalState();
	}

	/**
	 * Continue a login an administrator approved; also what "Check now"
	 * does while it still waits.
	 */
	#[NoAdminRequired]
	#[UseSession]
	#[UserRateLimit(limit: 60, period: 600)]
	#[FrontpageRoute(verb: 'POST', url: '/verify/approval/continue')]
	public function continueApproval(string $redirect_url = '', string $remember = ''): Response {
		return $this->pages->continueAfterApproval($redirect_url, $remember);
	}

	/**
	 * Give up waiting: the request is withdrawn and the login ends.
	 */
	#[NoAdminRequired]
	#[UseSession]
	#[UserRateLimit(limit: 10, period: 600)]
	#[FrontpageRoute(verb: 'POST', url: '/verify/approval/cancel')]
	public function cancelApproval(): Response {
		return $this->pages->cancelWaiting('');
	}

	/**
	 * Where a login, or a session whose sensitive action was not confirmed,
	 * ends. It shows nothing but a fixed text for the reason, so it may be
	 * public: the session is gone.
	 */
	#[PublicPage]
	#[NoCSRFRequired]
	#[FrontpageRoute(verb: 'GET', url: '/verify/ended')]
	public function ended(string $reason = ''): StandaloneTemplateResponse {
		$text = match ($reason) {
			StepUpFailed::RULE_ATTEMPTS => $this->l->t('The code was entered wrong too many times, so this login was ended. If it was you, log in again; a new code will be sent.'),
			StepUpFailed::RULE_TIMEOUT => $this->l->t('This login was not confirmed in time, so it was ended. If it was you, log in again.'),
			StepUpFailed::RULE_REJECTED => $this->l->t('An administrator rejected this login, so it was ended. If it was you, contact your administrator.'),
			ActionConfirmationFlow::ENDED_ATTEMPTS => $this->l->t('The code was entered wrong too many times, so your session was ended. If it was you, log in again.'),
			ActionConfirmationFlow::ENDED_REJECTED => $this->l->t('An administrator rejected the confirmation, so your session was ended. If it was you, contact your administrator.'),
			default => $this->l->t('This login was never confirmed, so it was ended. If it was you, log in again.'),
		};
		return $this->pages->render(self::MODE_ENDED, [
			'title' => in_array($reason, [ActionConfirmationFlow::ENDED_ATTEMPTS, ActionConfirmationFlow::ENDED_REJECTED], true) ? $this->l->t('Your session was ended') : $this->l->t('This login was ended'),
			'lead' => $text,
		]);
	}

	private function refusedPage(StepUpState $stepUp): StandaloneTemplateResponse {
		$response = $this->pages->render(self::MODE_REFUSED, [
			'title' => $this->l->t('This login needs extra confirmation'),
			'lead' => $this->l->t('This login needs extra confirmation, but your account has no email address or second factor that we could use. Please contact your administrator.'),
			'reference' => $stepUp->reference,
			'backUrl' => $this->urlGenerator->linkToRoute('core.login.showLoginForm'),
			'backLabel' => $this->l->t('Back to the login page'),
		]);
		$response->setStatus(Http::STATUS_FORBIDDEN);
		return $response;
	}
}
