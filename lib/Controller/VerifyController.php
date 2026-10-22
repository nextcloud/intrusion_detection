<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Controller;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\StepUpFailed;
use OCA\IntrusionDetection\Confirm\ConfirmationPolicy;
use OCA\IntrusionDetection\Confirm\EmailCodes;
use OCA\IntrusionDetection\Confirm\IConfirmationMethod;
use OCA\IntrusionDetection\Confirm\Methods\AdminApprovalMethod;
use OCA\IntrusionDetection\Confirm\Methods\SecondFactorMethod;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Confirm\StepUpService;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCA\IntrusionDetection\Explain\TextRenderer;
use OCA\IntrusionDetection\Http\LocalRedirect;
use OCA\IntrusionDetection\KnownDevice\KnownDevices;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
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
use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\Http\Response;
use OCP\AppFramework\Http\StandaloneTemplateResponse;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\IUserSession;
use OCP\Util;

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
	public const MODE_WAITING = 'waiting';
	/** Seconds between two status requests of the waiting page */
	public const POLL_INTERVAL = 10;

	public function __construct(
		IRequest $request,
		private readonly IUserSession $userSession,
		private readonly StepUpService $stepUps,
		private readonly EmailCodes $codes,
		private readonly ConfirmationPolicy $policy,
		private readonly IURLGenerator $urlGenerator,
		private readonly LocalRedirect $redirect,
		private readonly IL10N $l,
		private readonly KnownDevices $knownDevices,
		private readonly RemoteAddressResolver $addresses,
		private readonly ITimeFactory $timeFactory,
	) {
		parent::__construct(Application::APP_ID, $request);
	}

	#[NoAdminRequired]
	#[NoCSRFRequired]
	#[UseSession]
	#[FrontpageRoute(verb: 'GET', url: '/verify')]
	public function show(string $redirect_url = '', string $use = ''): Response {
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
		if ($stepUp->approvalId !== null && !($use === self::MODE_CODE && $stepUp->hasMethod(IConfirmationMethod::EMAIL_CODE))) {
			return $this->waitingPage($user, $stepUp, $redirect_url);
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
		string $remember = '',
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
				$this->rememberIfChosen($user, $remember);
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
		if ($stepUp->hasMethod(IConfirmationMethod::EMAIL_CODE) && $this->codes->isLimited($user)) {
			return $this->codePage($user, $stepUp, $redirect_url, $this->tooManyCodes());
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
	 * Ask an administrator to approve the login, instead of entering a code.
	 */
	#[NoAdminRequired]
	#[UseSession]
	#[UserRateLimit(limit: 5, period: 600)]
	#[FrontpageRoute(verb: 'POST', url: '/verify/approval')]
	public function requestApproval(string $redirect_url = ''): Response {
		[$user, $stepUp] = $this->current();
		if ($user === null || $stepUp === null || !$stepUp->isPending()) {
			return $this->continue($redirect_url);
		}
		$method = $this->approvalMethod($user, $stepUp);
		if ($method === null) {
			return $this->codePage($user, $stepUp, $redirect_url, $this->l->t('No administrator can be asked to approve this login.'));
		}
		if ($stepUp->approvalId !== null) {
			// A login asks once: a rejected, expired or vanished request ends it.
			$status = $method->status($user, $stepUp);
			if ($status === AdminApprovalMethod::STATUS_NONE) {
				$status = AdminApprovalMethod::STATUS_EXPIRED;
			}
			return $this->endByApproval($stepUp, $status) ?? $this->waitingPage($user, $stepUp, $redirect_url);
		}
		if ($method->begin($user, $stepUp) !== IConfirmationMethod::PENDING) {
			return $this->codePage($user, $stepUp, $redirect_url, $this->l->t('No administrator can be asked right now. Try again in a while, or contact your administrator.'));
		}
		$this->stepUps->save($stepUp);
		return $this->waitingPage($user, $stepUp, $redirect_url);
	}

	/**
	 * Whether an administrator decided on the waiting login: what the
	 * waiting page asks every few seconds. Read-only and cheap: one lookup in
	 * the session and one primary-key read.
	 */
	#[NoAdminRequired]
	#[NoCSRFRequired]
	#[UserRateLimit(limit: 120, period: 600)]
	#[FrontpageRoute(verb: 'GET', url: '/verify/approval/status')]
	public function approvalStatus(): JSONResponse {
		[$user, $stepUp] = $this->current();
		$method = $user === null || $stepUp === null || !$stepUp->isPending() ? null : $this->approvalMethod($user, $stepUp);
		$status = $method === null || $user === null || $stepUp === null ? AdminApprovalMethod::STATUS_NONE : $method->status($user, $stepUp);
		$response = new JSONResponse(['status' => $status, 'retryAfter' => self::POLL_INTERVAL]);
		$response->cacheFor(0);
		return $response;
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
		[$user, $stepUp] = $this->current();
		if ($user === null || $stepUp === null || !$stepUp->isPending()) {
			return $this->continue($redirect_url);
		}
		$method = $this->approvalMethod($user, $stepUp);
		$status = $method === null ? AdminApprovalMethod::STATUS_NONE : $method->status($user, $stepUp);
		$ended = $this->endByApproval($stepUp, $status);
		if ($ended !== null) {
			return $ended;
		}
		switch ($status) {
			case AdminApprovalMethod::STATUS_APPROVED:
				$this->stepUps->complete($stepUp, IConfirmationMethod::ADMIN_APPROVAL);
				$this->rememberIfChosen($user, $remember);
				return $this->continue($redirect_url);
			case AdminApprovalMethod::STATUS_PENDING:
				return $this->waitingPage($user, $stepUp, $redirect_url, $this->l->t('No administrator has decided yet. This page keeps checking.'));
			default:
				return $this->codePage($user, $stepUp, $redirect_url);
		}
	}

	/**
	 * Give up waiting: the request is withdrawn and the login ends.
	 */
	#[NoAdminRequired]
	#[UseSession]
	#[UserRateLimit(limit: 10, period: 600)]
	#[FrontpageRoute(verb: 'POST', url: '/verify/approval/cancel')]
	public function cancelApproval(): RedirectResponse {
		[$user, $stepUp] = $this->current();
		if ($user !== null && $stepUp !== null && $stepUp->isPending()) {
			$this->approvalMethod($user, $stepUp)?->withdraw($user, $stepUp);
			$this->stepUps->abandon($stepUp);
		}
		return new RedirectResponse($this->urlGenerator->linkToRoute('core.login.showLoginForm'));
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
			StepUpFailed::RULE_REJECTED => $this->l->t('An administrator rejected this login, so it was ended. If it was you, contact your administrator.'),
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
		$valid = TextRenderer::duration(EmailCodes::TTL, $this->l);
		$hasCode = $stepUp->hasMethod(IConfirmationMethod::EMAIL_CODE);
		$limited = $hasCode && $this->codes->isLimited($user);
		if ($limited && $stepUp->codeHash === null) {
			$error ??= $this->tooManyCodes();
		}
		$because = StepUpPolicy::describeAll($stepUp->policies, $this->l);
		$safeRedirect = LocalRedirect::isSafe($redirectUrl, self::EXCLUDED) ? $redirectUrl : '';
		$outsideNetworks = $stepUp->policies === [StepUpPolicy::AdminOutsideNetworks->value];
		$response = $this->render(self::MODE_CODE, [
			'title' => $this->l->t('Confirm it\'s you'),
			'lead' => match (true) {
				$outsideNetworks && $hasCode && $stepUp->codeHash !== null => $this->l->t('You logged in from outside your trusted networks, so we need to confirm it\'s you. We sent a 6-digit code to %1$s. It is valid for %2$s.', [$masked, $valid]),
				$outsideNetworks => $this->l->t('You logged in from outside your trusted networks, so we need to confirm it\'s you.'),
				$hasCode && $stepUp->codeHash !== null => $this->l->t('We noticed unusual activity around your login, so we need to confirm it\'s you. We sent a 6-digit code to %1$s. It is valid for %2$s.', [$masked, $valid]),
				default => $this->l->t('We noticed unusual activity around your login, so we need to confirm it\'s you.'),
			},
			'why' => $because === '' ? null : $this->l->t('This login needs it because %s.', [$because]),
			'error' => $error,
			'notice' => $notice,
			'hasCode' => $hasCode,
			'attemptsLeft' => $stepUp->attempts > 0 ? $this->l->n('%n try left.', '%n tries left.', $this->codes->attemptsLeft($stepUp)) : null,
			'canResend' => $hasCode && !$limited && $this->codes->canResend($stepUp),
			'secondFactor' => $this->secondFactorMethod($user, $stepUp) !== null,
			'askAdmin' => $this->approvalMethod($user, $stepUp) !== null,
			'waiting' => $stepUp->approvalId !== null,
			'canRemember' => $this->knownDevices->isEnabled(),
			'rememberHint' => $this->rememberHint($stepUp),
			'confirmAction' => $this->urlGenerator->linkToRoute(Application::APP_ID . '.Verify.confirm'),
			'resendAction' => $this->urlGenerator->linkToRoute(Application::APP_ID . '.Verify.resend'),
			'secondFactorAction' => $this->urlGenerator->linkToRoute(Application::APP_ID . '.Verify.secondFactor'),
			'askAdminAction' => $this->urlGenerator->linkToRoute(Application::APP_ID . '.Verify.requestApproval'),
			'waitingUrl' => $this->urlGenerator->linkToRoute(Application::APP_ID . '.Verify.show', $safeRedirect === '' ? [] : ['redirect_url' => $safeRedirect]),
			'redirect_url' => $safeRedirect,
		]);
		$response->setStatus($error === null ? Http::STATUS_OK : ($status === Http::STATUS_OK ? Http::STATUS_BAD_REQUEST : $status));
		return $response;
	}

	private function tooManyCodes(): string {
		return $this->l->t('Too many codes were sent to your email address in the last hour. Wait a while, then send a new one, or use the last code you received.');
	}

	private function waitingPage(IUser $user, StepUpState $stepUp, string $redirectUrl, ?string $notice = null): StandaloneTemplateResponse {
		$because = StepUpPolicy::describeAll($stepUp->policies, $this->l);
		$safeRedirect = LocalRedirect::isSafe($redirectUrl, self::EXCLUDED) ? $redirectUrl : '';
		$expiresAt = $this->approvalMethod($user, $stepUp)?->expiresAt($user, $stepUp) ?? $stepUp->deadline;
		// Whole minutes: "30 minutes", not "1799 seconds".
		$left = max(60, (int)ceil(($expiresAt - $this->timeFactory->getTime()) / 60) * 60);
		Util::addScript(Application::APP_ID, 'verify');
		return $this->render(self::MODE_WAITING, [
			'title' => $this->l->t('Waiting for an administrator'),
			'lead' => $this->l->t('An administrator needs to confirm this login. You can keep this page open; it continues automatically once approved.'),
			'why' => $because === '' ? null : $this->l->t('This login needs it because %s.', [$because]),
			'notice' => $notice,
			'expires' => $this->l->t('If nobody decides within %s, the login ends and you can try again.', [TextRenderer::duration($left, $this->l)]),
			'hasCode' => $stepUp->hasMethod(IConfirmationMethod::EMAIL_CODE),
			'codeUrl' => $this->urlGenerator->linkToRoute(Application::APP_ID . '.Verify.show', array_filter(['use' => self::MODE_CODE, 'redirect_url' => $safeRedirect])),
			'canRemember' => $this->knownDevices->isEnabled(),
			'rememberHint' => $this->rememberHint($stepUp),
			'statusUrl' => $this->urlGenerator->linkToRoute(Application::APP_ID . '.Verify.approvalStatus'),
			'pollInterval' => self::POLL_INTERVAL,
			'continueAction' => $this->urlGenerator->linkToRoute(Application::APP_ID . '.Verify.continueApproval'),
			'cancelAction' => $this->urlGenerator->linkToRoute(Application::APP_ID . '.Verify.cancelApproval'),
			'redirect_url' => $safeRedirect,
		]);
	}

	private function refusedPage(StepUpState $stepUp): StandaloneTemplateResponse {
		$because = StepUpPolicy::describeAll($stepUp->policies, $this->l);
		$response = $this->render(self::MODE_REFUSED, [
			'title' => $this->l->t('This login needs extra confirmation'),
			'lead' => $this->l->t('Your account has no email address or second factor that could confirm it, so this login cannot continue.'),
			'why' => $because === '' ? null : $this->l->t('This login needs it because %s.', [$because]),
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

	private function rememberHint(StepUpState $stepUp): string {
		$for = TextRenderer::duration(KnownDevices::DURATION, $this->l);
		return in_array(StepUpPolicy::AdminOutsideNetworks->value, $stepUp->policies, true)
			? $this->l->t('Only on your own device. For %s, logins from this browser are confirmed without asking again, unless your password itself is at risk or you log in from outside your trusted networks.', [$for])
			: $this->l->t('Only on your own device. For %s, logins from this browser are confirmed without asking again, unless your password itself is at risk.', [$for]);
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

	private function approvalMethod(IUser $user, StepUpState $stepUp): ?AdminApprovalMethod {
		if (!$stepUp->hasMethod(IConfirmationMethod::ADMIN_APPROVAL)) {
			return null;
		}
		$method = $this->policy->method(IConfirmationMethod::ADMIN_APPROVAL);
		if (!$method instanceof AdminApprovalMethod) {
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

	/**
	 * End the login when its request for approval was rejected or has
	 * expired.
	 *
	 * @param AdminApprovalMethod::STATUS_* $status
	 * @return ?RedirectResponse the page that says why, or null when the login goes on
	 */
	private function endByApproval(StepUpState $stepUp, string $status): ?RedirectResponse {
		$rule = match ($status) {
			AdminApprovalMethod::STATUS_REJECTED => StepUpFailed::RULE_REJECTED,
			AdminApprovalMethod::STATUS_EXPIRED => StepUpFailed::RULE_TIMEOUT,
			default => null,
		};
		if ($rule === null) {
			return null;
		}
		$this->stepUps->fail($stepUp, $rule);
		return new RedirectResponse($this->urlGenerator->linkToRoute(Application::APP_ID . '.Verify.ended', ['reason' => $rule]));
	}

	/**
	 * After a confirmed login: remember this browser, when the user ticked it.
	 */
	private function rememberIfChosen(IUser $user, string $remember): void {
		if ($remember === '1') {
			$this->knownDevices->remember($user, $this->addresses->current(), $this->request->getHeader('User-Agent'));
		}
	}

	private function continue(string $redirectUrl): RedirectResponse {
		return new RedirectResponse($this->redirect->target($redirectUrl, self::EXCLUDED));
	}
}
