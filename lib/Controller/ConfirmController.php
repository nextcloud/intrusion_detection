<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Controller;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Confirm\ConfirmationPages;
use OCA\IntrusionDetection\Confirm\ConfirmationPolicy;
use OCA\IntrusionDetection\Confirm\EmailCodes;
use OCA\IntrusionDetection\Confirm\IConfirmationMethod;
use OCA\IntrusionDetection\Http\LocalRedirect;
use OCA\IntrusionDetection\KnownDevice\KnownDevices;
use OCA\IntrusionDetection\Lockdown\LockdownState;
use OCA\IntrusionDetection\Sensitive\ActionConfirmationFlow;
use OCA\IntrusionDetection\Sensitive\SensitiveConfirmations;
use OCA\IntrusionDetection\Sensitive\SensitiveSession;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\BruteForceProtection;
use OCP\AppFramework\Http\Attribute\FrontpageRoute;
use OCP\AppFramework\Http\Attribute\NoAdminRequired;
use OCP\AppFramework\Http\Attribute\NoCSRFRequired;
use OCP\AppFramework\Http\Attribute\OpenAPI;
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
 * The confirm page (concept sections 11.13 and 15.2): a risky session
 * confirms here before a sensitive action, then returns to the page it
 * came from and does the action again. The dialog of the confirm-dialog
 * script, or a redirect, brings the user here.
 *
 * The methods and their order are those of logins, without a remembered
 * device: the second factor (core's challenge, asked again), an email
 * code, an administrator's approval. The pages and their actions are the
 * verify page's ({@see ConfirmationPages}, {@see ActionConfirmationFlow}).
 * Without any method, the page says so and the action stays refused.
 *
 * Every state change is a CSRF-protected POST, rate limited per user, and
 * wrong codes are throttled together with those of the verify page. Too
 * many wrong codes, or a rejection by an administrator, end the session,
 * like a login that was not confirmed. A confirmation lasts
 * `sensitive_confirm_ttl`.
 */
#[OpenAPI(scope: OpenAPI::SCOPE_IGNORE)]
class ConfirmController extends Controller {
	public const BRUTE_FORCE_ACTION = ConfirmationPages::BRUTE_FORCE_ACTION;
	public const EXCLUDED = ActionConfirmationFlow::EXCLUDED;
	public const ENDED_ATTEMPTS = ActionConfirmationFlow::ENDED_ATTEMPTS;
	public const ENDED_REJECTED = ActionConfirmationFlow::ENDED_REJECTED;
	public const MODE_CODE = ConfirmationPages::MODE_CODE;
	public const MODE_REFUSED = ConfirmationPages::MODE_REFUSED;
	public const MODE_WAITING = ConfirmationPages::MODE_WAITING;

	private readonly ConfirmationPages $pages;

	public function __construct(
		IRequest $request,
		private readonly IUserSession $userSession,
		private readonly SensitiveConfirmations $confirmations,
		private readonly SensitiveSession $sensitive,
		private readonly SessionState $state,
		private readonly LockdownState $lockdown,
		EmailCodes $codes,
		ConfirmationPolicy $policy,
		Settings $settings,
		private readonly IURLGenerator $urlGenerator,
		private readonly LocalRedirect $redirect,
		private readonly IL10N $l,
		KnownDevices $knownDevices,
		private readonly ITimeFactory $timeFactory,
	) {
		parent::__construct(Application::APP_ID, $request);
		$flow = new ActionConfirmationFlow($confirmations, $sensitive, $state, $userSession, $settings, $redirect, $urlGenerator, $l);
		$this->pages = new ConfirmationPages($flow, $userSession, $codes, $policy, $settings, $urlGenerator, $redirect, $l, $knownDevices, $timeFactory);
	}

	/**
	 * Start confirming, or show the confirmation in progress. A session
	 * that confirmed recently goes straight back.
	 */
	#[NoAdminRequired]
	#[NoCSRFRequired]
	#[UseSession]
	#[UserRateLimit(limit: 30, period: 600)]
	#[FrontpageRoute(verb: 'GET', url: '/confirm')]
	public function show(string $redirect_url = '', string $use = ''): Response {
		$user = $this->userSession->getUser();
		if ($user === null) {
			return $this->pages->continue($redirect_url);
		}
		$pending = $this->confirmations->current($user);
		if ($pending === null || !$pending->isPending()) {
			if ($this->sensitive->isConfirmed($this->state, $user->getUID())) {
				return $this->pages->continue($redirect_url);
			}
			$pending = $this->confirmations->start($user);
			if ($pending === null) {
				return $this->refusedPage($redirect_url);
			}
		}
		if ($pending->approvalId !== null && !($use === self::MODE_CODE && $pending->hasMethod(IConfirmationMethod::EMAIL_CODE))) {
			return $this->pages->waitingPage($user, $pending, $redirect_url);
		}
		return $this->pages->codePage($user, $pending, $redirect_url);
	}

	#[NoAdminRequired]
	#[UseSession]
	#[UserRateLimit(limit: 20, period: 600)]
	#[BruteForceProtection(action: self::BRUTE_FORCE_ACTION)]
	#[FrontpageRoute(verb: 'POST', url: '/confirm')]
	public function confirm(
		#[\SensitiveParameter]
		string $code = '',
		string $redirect_url = '',
	): Response {
		return $this->pages->confirmCode($code, $redirect_url, '');
	}

	#[NoAdminRequired]
	#[UseSession]
	#[UserRateLimit(limit: 10, period: 600)]
	#[FrontpageRoute(verb: 'POST', url: '/confirm/resend')]
	public function resend(string $redirect_url = ''): Response {
		return $this->pages->resendCode($redirect_url);
	}

	#[NoAdminRequired]
	#[UseSession]
	#[UserRateLimit(limit: 10, period: 600)]
	#[FrontpageRoute(verb: 'POST', url: '/confirm/second-factor')]
	public function secondFactor(string $redirect_url = ''): Response {
		return $this->pages->askSecondFactor($redirect_url);
	}

	#[NoAdminRequired]
	#[UseSession]
	#[UserRateLimit(limit: 5, period: 600)]
	#[FrontpageRoute(verb: 'POST', url: '/confirm/approval')]
	public function requestApproval(string $redirect_url = ''): Response {
		return $this->pages->askAdministrator($redirect_url);
	}

	#[NoAdminRequired]
	#[NoCSRFRequired]
	#[UserRateLimit(limit: 120, period: 600)]
	#[FrontpageRoute(verb: 'GET', url: '/confirm/approval/status')]
	public function approvalStatus(): JSONResponse {
		return $this->pages->approvalState();
	}

	#[NoAdminRequired]
	#[UseSession]
	#[UserRateLimit(limit: 60, period: 600)]
	#[FrontpageRoute(verb: 'POST', url: '/confirm/approval/continue')]
	public function continueApproval(string $redirect_url = ''): Response {
		return $this->pages->continueAfterApproval($redirect_url, '');
	}

	#[NoAdminRequired]
	#[UseSession]
	#[UserRateLimit(limit: 10, period: 600)]
	#[FrontpageRoute(verb: 'POST', url: '/confirm/approval/cancel')]
	public function cancelApproval(string $redirect_url = ''): Response {
		return $this->pages->cancelWaiting($redirect_url);
	}

	/**
	 * Where a browser is sent that tried to connect a new device during
	 * lockdown.
	 */
	#[NoAdminRequired]
	#[NoCSRFRequired]
	#[FrontpageRoute(verb: 'GET', url: '/confirm/unavailable')]
	public function unavailable(): StandaloneTemplateResponse {
		$response = $this->pages->render(self::MODE_REFUSED, [
			'title' => $this->l->t('Not possible right now'),
			'lead' => $this->l->t('New devices cannot be connected right now. Please try again later.'),
			'hint' => $this->lockdown->isActive()
				? $this->l->t('Your administrator turned on extra security checks until %s. Devices that are already connected keep working.', [(string)$this->l->l('datetime', $this->lockdown->until(), ['width' => 'short'])])
				: null,
			'backUrl' => $this->urlGenerator->linkToDefaultPageUrl(),
			'backLabel' => $this->l->t('Back to Nextcloud'),
		]);
		$response->setStatus(Http::STATUS_FORBIDDEN);
		return $response;
	}

	private function refusedPage(string $redirectUrl): StandaloneTemplateResponse {
		$response = $this->pages->render(self::MODE_REFUSED, [
			'title' => $this->l->t('This needs extra confirmation'),
			'lead' => $this->l->t('This action needs extra confirmation, but your account has no email address or second factor. Ask your administrator.'),
			'backUrl' => $this->redirect->target($redirectUrl, self::EXCLUDED),
			'backLabel' => $this->l->t('Back'),
		]);
		$response->setStatus(Http::STATUS_FORBIDDEN);
		return $response;
	}
}
