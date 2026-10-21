<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Controller;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\StepUpFailed;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Confirm\ConfirmationPolicy;
use OCA\IntrusionDetection\Confirm\EmailCodes;
use OCA\IntrusionDetection\Confirm\IConfirmationMethod;
use OCA\IntrusionDetection\Confirm\Methods\SecondFactorMethod;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Confirm\StepUpService;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCA\IntrusionDetection\Explain\TextRenderer;
use OCA\IntrusionDetection\Http\LocalRedirect;
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
use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\Http\Response;
use OCP\AppFramework\Http\StandaloneTemplateResponse;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\IUserSession;
use OCP\Util;

/**
 * The verify page (concept sections 11.5 and 15.2): a login that needs
 * extra confirmation is held here until the code sent by email is entered
 * (or the second factor, where the account has one). A refused login is
 * told why, with a reference, and ended. A login that could not be
 * confirmed ends on a public page that only says so.
 *
 * Every state change is a CSRF-protected POST, rate limited per user, and
 * wrong codes are throttled like failed logins. There is no
 * #[NoTwoFactorRequired]: an account with a second factor is confirmed by
 * core's challenge at login and never sent here, so a session that still
 * waits for its second factor goes to the challenge first. Codes are never
 * logged or kept; only their hash is in the session.
 */
#[OpenAPI(scope: OpenAPI::SCOPE_IGNORE)]
class VerifyController extends Controller {
	public const TEMPLATE = 'verify';
	public const BRUTE_FORCE_ACTION = 'intrusion_detection_verify';
	/** Never continued to: the verify pages themselves */
	public const EXCLUDED = ['/apps/' . Application::APP_ID . '/verify'];

	public const MODE_CODE = 'code';
	public const MODE_REFUSED = 'refused';
	public const MODE_ENDED = 'ended';

	public function __construct(
		IRequest $request,
		private readonly IUserSession $userSession,
		private readonly StepUpService $stepUps,
		private readonly EmailCodes $codes,
		private readonly ConfirmationPolicy $policy,
		private readonly Settings $settings,
		private readonly IURLGenerator $urlGenerator,
		private readonly LocalRedirect $redirect,
		private readonly IL10N $l,
	) {
		parent::__construct(Application::APP_ID, $request);
	}

	#[NoAdminRequired]
	#[NoCSRFRequired]
	#[UseSession]
	#[FrontpageRoute(verb: 'GET', url: '/verify')]
	public function show(string $redirect_url = ''): Response {
		[$user, $stepUp] = $this->current();
		if ($user === null || $stepUp === null) {
			return $this->continue($redirect_url);
		}
		if ($stepUp->status === StepUpState::REFUSED) {
			$response = $this->refusedPage($stepUp);
			$this->stepUps->endRefused();
			return $response;
		}
		if (!$stepUp->isPending()) {
			return $this->continue($redirect_url);
		}
		return $this->codePage($user, $stepUp, $redirect_url);
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
	): Response {
		[$user, $stepUp] = $this->current();
		if ($user === null || $stepUp === null || !$stepUp->isPending()) {
			return $this->continue($redirect_url);
		}
		if (!$stepUp->hasMethod(IConfirmationMethod::EMAIL_CODE)) {
			return $this->codePage($user, $stepUp, $redirect_url, $this->l->t('This login cannot be confirmed with a code.'));
		}
		$result = $this->codes->verify($stepUp, $code);
		switch ($result) {
			case EmailCodes::VERIFIED:
				$this->stepUps->complete($stepUp, IConfirmationMethod::EMAIL_CODE);
				return $this->continue($redirect_url);
			case EmailCodes::EXHAUSTED:
				$this->stepUps->fail($stepUp, StepUpFailed::RULE_ATTEMPTS);
				$response = new RedirectResponse($this->urlGenerator->linkToRoute(Application::APP_ID . '.Verify.ended', ['reason' => StepUpFailed::RULE_ATTEMPTS]));
				$response->throttle();
				return $response;
			case EmailCodes::WRONG:
				$this->stepUps->save($stepUp);
				$left = $this->codes->attemptsLeft($stepUp);
				$response = $this->codePage($user, $stepUp, $redirect_url, $this->l->n('This code is not correct. You can try %n more time.', 'This code is not correct. You can try %n more times.', $left), status: Http::STATUS_FORBIDDEN);
				$response->throttle();
				return $response;
			case EmailCodes::EXPIRED:
				return $this->codePage($user, $stepUp, $redirect_url, $this->l->t('This code has expired. Send a new one, then enter it.'));
			default:
				return $this->codePage($user, $stepUp, $redirect_url, $this->l->t('Enter the 6 digits from the email.'));
		}
	}

	#[NoAdminRequired]
	#[UseSession]
	#[UserRateLimit(limit: 10, period: 600)]
	#[FrontpageRoute(verb: 'POST', url: '/verify/resend')]
	public function resend(string $redirect_url = ''): Response {
		[$user, $stepUp] = $this->current();
		if ($user === null || $stepUp === null || !$stepUp->isPending()) {
			return $this->continue($redirect_url);
		}
		if (!$stepUp->hasMethod(IConfirmationMethod::EMAIL_CODE) || !$this->codes->canResend($stepUp)) {
			return $this->codePage($user, $stepUp, $redirect_url, $this->l->t('No more codes can be sent for a few minutes. Use the last code you received, or wait and try again.'));
		}
		$sent = $this->codes->resend($user, $stepUp);
		$this->stepUps->save($stepUp);
		return $sent
			? $this->codePage($user, $stepUp, $redirect_url, notice: $this->l->t('A new code was sent to %s. Earlier codes no longer work.', [EmailCodes::mask((string)$user->getEMailAddress())]))
			: $this->codePage($user, $stepUp, $redirect_url, $this->l->t('The email could not be sent. Try again in a moment, or contact your administrator.'));
	}

	#[NoAdminRequired]
	#[UseSession]
	#[UserRateLimit(limit: 10, period: 600)]
	#[FrontpageRoute(verb: 'POST', url: '/verify/second-factor')]
	public function secondFactor(string $redirect_url = ''): Response {
		[$user, $stepUp] = $this->current();
		if ($user === null || $stepUp === null || !$stepUp->isPending()) {
			return $this->continue($redirect_url);
		}
		$method = $this->secondFactorMethod($user, $stepUp);
		if ($method === null) {
			return $this->codePage($user, $stepUp, $redirect_url, $this->l->t('Your account has no second factor that could confirm this login.'));
		}
		$stepUp->secondFactorRequested = true;
		$this->stepUps->save($stepUp);
		$back = $this->urlGenerator->linkToRoute(Application::APP_ID . '.Verify.show', LocalRedirect::isSafe($redirect_url, self::EXCLUDED) ? ['redirect_url' => $redirect_url] : []);
		try {
			return new RedirectResponse($method->requestChallenge($user, $back));
		} catch (\LogicException) {
			return $this->codePage($user, $stepUp, $redirect_url, $this->l->t('Your account has no second factor that could confirm this login.'));
		}
	}

	/**
	 * Where a login ends that could not be confirmed. It shows nothing but a
	 * fixed text for the reason, so it may be public: the session is gone.
	 */
	#[PublicPage]
	#[NoCSRFRequired]
	#[FrontpageRoute(verb: 'GET', url: '/verify/ended')]
	public function ended(string $reason = ''): StandaloneTemplateResponse {
		$text = match ($reason) {
			StepUpFailed::RULE_ATTEMPTS => $this->l->t('The code was entered wrong too many times, so this login was ended. If it was you, log in again; a new code will be sent.'),
			StepUpFailed::RULE_TIMEOUT => $this->l->t('This login was not confirmed in time, so it was ended. If it was you, log in again.'),
			default => $this->l->t('This login was never confirmed, so it was ended. If it was you, log in again.'),
		};
		return $this->render(self::MODE_ENDED, [
			'title' => $this->l->t('This login was ended'),
			'lead' => $text,
		]);
	}

	/**
	 * @return array{0: ?IUser, 1: ?StepUpState} the logged-in user and the session's step-up, if it is theirs
	 */
	private function current(): array {
		$user = $this->userSession->getUser();
		$stepUp = $this->stepUps->current();
		if ($user === null || $stepUp === null || $stepUp->uid !== $user->getUID()) {
			return [$user, null];
		}
		return [$user, $stepUp];
	}

	private function codePage(IUser $user, StepUpState $stepUp, string $redirectUrl, ?string $error = null, ?string $notice = null, int $status = Http::STATUS_OK): StandaloneTemplateResponse {
		$masked = EmailCodes::mask((string)$user->getEMailAddress());
		$valid = TextRenderer::duration($this->settings->getInt(GlobalSettings::STEP_UP_CODE_TTL), $this->l);
		$hasCode = $stepUp->hasMethod(IConfirmationMethod::EMAIL_CODE);
		$because = StepUpPolicy::describeAll($stepUp->policies, $this->l);
		$safeRedirect = LocalRedirect::isSafe($redirectUrl, self::EXCLUDED) ? $redirectUrl : '';
		$response = $this->render(self::MODE_CODE, [
			'title' => $this->l->t('Confirm it\'s you'),
			'lead' => $hasCode
				? $this->l->t('We noticed unusual activity around your login, so we need to confirm it\'s you. We sent a 6-digit code to %1$s. It is valid for %2$s.', [$masked, $valid])
				: $this->l->t('We noticed unusual activity around your login, so we need to confirm it\'s you.'),
			'why' => $because === '' ? null : $this->l->t('This login needs it because %s.', [$because]),
			'error' => $error,
			'notice' => $notice,
			'hasCode' => $hasCode,
			'attemptsLeft' => $stepUp->attempts > 0 ? $this->l->n('%n try left.', '%n tries left.', $this->codes->attemptsLeft($stepUp)) : null,
			'canResend' => $hasCode && $this->codes->canResend($stepUp),
			'secondFactor' => $this->secondFactorMethod($user, $stepUp) !== null,
			'confirmAction' => $this->urlGenerator->linkToRoute(Application::APP_ID . '.Verify.confirm'),
			'resendAction' => $this->urlGenerator->linkToRoute(Application::APP_ID . '.Verify.resend'),
			'secondFactorAction' => $this->urlGenerator->linkToRoute(Application::APP_ID . '.Verify.secondFactor'),
			'redirect_url' => $safeRedirect,
		]);
		$response->setStatus($error === null ? Http::STATUS_OK : ($status === Http::STATUS_OK ? Http::STATUS_BAD_REQUEST : $status));
		return $response;
	}

	private function refusedPage(StepUpState $stepUp): StandaloneTemplateResponse {
		$response = $this->render(self::MODE_REFUSED, [
			'title' => $this->l->t('This login needs extra confirmation'),
			'lead' => $this->l->t('This login needs extra confirmation, but your account has no email address or second factor that we could use. Please contact your administrator.'),
			'reference' => $stepUp->reference,
		]);
		$response->setStatus(Http::STATUS_FORBIDDEN);
		return $response;
	}

	/**
	 * @param array<string, mixed> $params
	 */
	private function render(string $mode, array $params): StandaloneTemplateResponse {
		Util::addStyle(Application::APP_ID, 'pages');
		return new StandaloneTemplateResponse(Application::APP_ID, self::TEMPLATE, array_merge([
			'mode' => $mode,
			'logout_url' => $this->urlGenerator->getLogoutUrl(),
			'login_url' => $this->urlGenerator->linkToRoute('core.login.showLoginForm'),
		], $params), 'guest');
	}

	private function secondFactorMethod(IUser $user, StepUpState $stepUp): ?SecondFactorMethod {
		if (!$stepUp->hasMethod(IConfirmationMethod::SECOND_FACTOR)) {
			return null;
		}
		$method = $this->policy->method(IConfirmationMethod::SECOND_FACTOR);
		if (!$method instanceof SecondFactorMethod) {
			return null;
		}
		foreach ($stepUp->policies as $policy) {
			$known = StepUpPolicy::tryFrom($policy);
			if ($known === null || !$method->isAvailable($user, $known)) {
				return null;
			}
		}
		return $method;
	}

	private function continue(string $redirectUrl): RedirectResponse {
		return new RedirectResponse($this->redirect->target($redirectUrl, self::EXCLUDED));
	}
}
