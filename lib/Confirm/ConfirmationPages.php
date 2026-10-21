<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\StepUpFailed;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Confirm\Methods\AdminApprovalMethod;
use OCA\IntrusionDetection\Confirm\Methods\SecondFactorMethod;
use OCA\IntrusionDetection\Explain\TextRenderer;
use OCA\IntrusionDetection\Http\LocalRedirect;
use OCA\IntrusionDetection\KnownDevice\KnownDevices;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\JSONResponse;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\Http\Response;
use OCP\AppFramework\Http\StandaloneTemplateResponse;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IL10N;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\IUserSession;
use OCP\Util;

/**
 * The pages that confirm it is really the account holder (concept sections
 * 11.5 and 15.2): an email code, the second factor through core's
 * challenge, or an administrator's approval, on one guest page
 * (templates/verify.php) with the waiting page's status polling.
 *
 * Two flows use them: confirming a login (the verify page) and confirming
 * a sensitive action in a running session (the confirm page). Each flow
 * ({@see IConfirmationFlow}) says where its confirmation in progress is
 * kept, what completing and failing it does, its routes and its texts; its
 * controller declares the routes and calls the actions here.
 *
 * Codes are never logged or kept; only their hash is in the session.
 */
class ConfirmationPages {
	public const TEMPLATE = 'verify';
	public const BRUTE_FORCE_ACTION = 'intrusion_detection_verify';

	public const MODE_CODE = 'code';
	public const MODE_REFUSED = 'refused';
	public const MODE_ENDED = 'ended';
	public const MODE_WAITING = 'waiting';
	/** Seconds between two status requests of the waiting page */
	public const POLL_INTERVAL = 10;

	public function __construct(
		private readonly IConfirmationFlow $flow,
		private readonly IUserSession $userSession,
		private readonly EmailCodes $codes,
		private readonly ConfirmationPolicy $policy,
		private readonly Settings $settings,
		private readonly IURLGenerator $urlGenerator,
		private readonly LocalRedirect $redirect,
		private readonly IL10N $l,
		private readonly KnownDevices $knownDevices,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	public function confirmCode(#[\SensitiveParameter] string $code, string $redirectUrl, string $remember): Response {
		[$user, $pending] = $this->current();
		if ($user === null || $pending === null) {
			return $this->continue($redirectUrl);
		}
		if (!$pending->hasMethod(IConfirmationMethod::EMAIL_CODE)) {
			return $this->codePage($user, $pending, $redirectUrl, $this->l->t('This cannot be confirmed with a code.'));
		}
		$result = $this->codes->verify($pending, $code);
		switch ($result) {
			case EmailCodes::VERIFIED:
				$this->flow->complete($user, $pending, IConfirmationMethod::EMAIL_CODE, $remember);
				return $this->continue($redirectUrl);
			case EmailCodes::EXHAUSTED:
				$response = $this->flow->fail($pending, StepUpFailed::RULE_ATTEMPTS);
				$response->throttle();
				return $response;
			case EmailCodes::WRONG:
				$this->flow->save($pending);
				$left = $this->codes->attemptsLeft($pending);
				$response = $this->codePage($user, $pending, $redirectUrl, $this->l->n('This code is not correct. You can try %n more time.', 'This code is not correct. You can try %n more times.', $left), status: Http::STATUS_FORBIDDEN);
				$response->throttle();
				return $response;
			case EmailCodes::EXPIRED:
				return $this->codePage($user, $pending, $redirectUrl, $this->l->t('This code has expired. Send a new one, then enter it.'));
			default:
				return $this->codePage($user, $pending, $redirectUrl, $this->l->t('Enter the 6 digits from the email.'));
		}
	}

	public function resendCode(string $redirectUrl): Response {
		[$user, $pending] = $this->current();
		if ($user === null || $pending === null) {
			return $this->continue($redirectUrl);
		}
		if (!$pending->hasMethod(IConfirmationMethod::EMAIL_CODE) || !$this->codes->canResend($pending)) {
			return $this->codePage($user, $pending, $redirectUrl, $this->l->t('No more codes can be sent for a few minutes. Use the last code you received, or wait and try again.'));
		}
		$sent = $this->codes->resend($user, $pending);
		$this->flow->save($pending);
		return $sent
			? $this->codePage($user, $pending, $redirectUrl, notice: $this->l->t('A new code was sent to %s. Earlier codes no longer work.', [EmailCodes::mask((string)$user->getEMailAddress())]))
			: $this->codePage($user, $pending, $redirectUrl, $this->l->t('The email could not be sent. Try again in a moment, or contact your administrator.'));
	}

	public function askSecondFactor(string $redirectUrl): Response {
		[$user, $pending] = $this->current();
		if ($user === null || $pending === null) {
			return $this->continue($redirectUrl);
		}
		$method = $this->secondFactorMethod($user, $pending);
		if ($method === null) {
			return $this->codePage($user, $pending, $redirectUrl, $this->l->t('Your account has no second factor that could confirm this.'));
		}
		$pending->secondFactorRequested = true;
		$this->flow->save($pending);
		$back = $this->urlGenerator->linkToRoute($this->flow->route('show'), LocalRedirect::isSafe($redirectUrl, $this->flow->excluded()) ? ['redirect_url' => $redirectUrl] : []);
		try {
			return new RedirectResponse($method->requestChallenge($user, $back));
		} catch (\LogicException) {
			return $this->codePage($user, $pending, $redirectUrl, $this->l->t('Your account has no second factor that could confirm this.'));
		}
	}

	public function askAdministrator(string $redirectUrl): Response {
		[$user, $pending] = $this->current();
		if ($user === null || $pending === null) {
			return $this->continue($redirectUrl);
		}
		$method = $this->approvalMethod($user, $pending);
		if ($method === null) {
			return $this->codePage($user, $pending, $redirectUrl, $this->l->t('No administrator can be asked to approve this.'));
		}
		if ($pending->approvalId !== null && $method->status($user, $pending) === AdminApprovalMethod::STATUS_PENDING) {
			return $this->waitingPage($user, $pending, $redirectUrl);
		}
		if ($method->begin($user, $pending) !== IConfirmationMethod::PENDING) {
			return $this->codePage($user, $pending, $redirectUrl, $this->l->t('No administrator can be asked right now. Try again in a while, or contact your administrator.'));
		}
		$this->flow->save($pending);
		return $this->waitingPage($user, $pending, $redirectUrl);
	}

	/**
	 * Whether an administrator decided: what the waiting page asks every few
	 * seconds. One lookup in the session and one primary-key read.
	 */
	public function approvalState(): JSONResponse {
		[$user, $pending] = $this->current();
		$method = $user === null || $pending === null ? null : $this->approvalMethod($user, $pending);
		$status = $method === null || $user === null || $pending === null ? AdminApprovalMethod::STATUS_NONE : $method->status($user, $pending);
		$response = new JSONResponse(['status' => $status, 'retryAfter' => self::POLL_INTERVAL]);
		$response->cacheFor(0);
		return $response;
	}

	/**
	 * Continue once an administrator approved; also what "Check now" does
	 * while it still waits.
	 */
	public function continueAfterApproval(string $redirectUrl, string $remember): Response {
		[$user, $pending] = $this->current();
		if ($user === null || $pending === null) {
			return $this->continue($redirectUrl);
		}
		$method = $this->approvalMethod($user, $pending);
		$status = $method === null ? AdminApprovalMethod::STATUS_NONE : $method->status($user, $pending);
		switch ($status) {
			case AdminApprovalMethod::STATUS_APPROVED:
				$this->flow->complete($user, $pending, IConfirmationMethod::ADMIN_APPROVAL, $remember);
				return $this->continue($redirectUrl);
			case AdminApprovalMethod::STATUS_REJECTED:
				return $this->flow->fail($pending, StepUpFailed::RULE_REJECTED);
			case AdminApprovalMethod::STATUS_EXPIRED:
				return $this->flow->fail($pending, StepUpFailed::RULE_TIMEOUT);
			case AdminApprovalMethod::STATUS_PENDING:
				return $this->waitingPage($user, $pending, $redirectUrl, $this->l->t('No administrator has decided yet. This page keeps checking.'));
			default:
				return $this->codePage($user, $pending, $redirectUrl);
		}
	}

	/**
	 * Give up waiting: the request is withdrawn.
	 */
	public function cancelWaiting(string $redirectUrl): Response {
		[$user, $pending] = $this->current();
		if ($user === null || $pending === null) {
			return $this->continue($redirectUrl);
		}
		$this->approvalMethod($user, $pending)?->withdraw($user, $pending);
		return $this->flow->giveUp($user, $pending, $redirectUrl);
	}

	/**
	 * @return array{0: ?IUser, 1: ?StepUpState} the logged-in user and their confirmation in progress, if it is pending
	 */
	public function current(): array {
		$user = $this->userSession->getUser();
		$pending = $user === null ? null : $this->flow->pending($user);
		if ($user === null || $pending === null || $pending->uid !== $user->getUID() || !$pending->isPending()) {
			return [$user, null];
		}
		return [$user, $pending];
	}

	public function codePage(IUser $user, StepUpState $pending, string $redirectUrl, ?string $error = null, ?string $notice = null, int $status = Http::STATUS_OK): StandaloneTemplateResponse {
		$texts = $this->textsFor($user, $pending, 0);
		$hasCode = $pending->hasMethod(IConfirmationMethod::EMAIL_CODE);
		$codeSent = $hasCode && $pending->codeHash !== null;
		$safeRedirect = $this->safe($redirectUrl);
		$escape = $this->flow->escape($safeRedirect);
		$response = $this->render(self::MODE_CODE, [
			'title' => $texts['title'],
			'lead' => $codeSent ? $texts['leadCode'] : $texts['lead'],
			'why' => $texts['why'],
			'error' => $error,
			'notice' => $notice,
			'hasCode' => $codeSent,
			'attemptsLeft' => $pending->attempts > 0 ? $this->l->n('%n try left.', '%n tries left.', $this->codes->attemptsLeft($pending)) : null,
			'canResend' => $hasCode && $this->codes->canResend($pending),
			'resendLabel' => $codeSent ? $this->l->t('Send a new code') : $this->l->t('Send a code by email'),
			'secondFactor' => $this->secondFactorMethod($user, $pending) !== null,
			'askAdmin' => $this->approvalMethod($user, $pending) !== null,
			'waiting' => $pending->approvalId !== null,
			'canRemember' => $this->flow->canRemember(),
			'rememberFor' => TextRenderer::duration($this->knownDevices->duration(), $this->l),
			'warning' => $texts['warning'],
			'escapeUrl' => $escape['url'],
			'escapeLabel' => $escape['label'],
			'confirmAction' => $this->urlGenerator->linkToRoute($this->flow->route('confirm')),
			'resendAction' => $this->urlGenerator->linkToRoute($this->flow->route('resend')),
			'secondFactorAction' => $this->urlGenerator->linkToRoute($this->flow->route('secondFactor')),
			'askAdminAction' => $this->urlGenerator->linkToRoute($this->flow->route('requestApproval')),
			'waitingUrl' => $this->urlGenerator->linkToRoute($this->flow->route('show'), $safeRedirect === '' ? [] : ['redirect_url' => $safeRedirect]),
			'redirect_url' => $safeRedirect,
		]);
		$response->setStatus($error === null ? Http::STATUS_OK : ($status === Http::STATUS_OK ? Http::STATUS_BAD_REQUEST : $status));
		return $response;
	}

	public function waitingPage(IUser $user, StepUpState $pending, string $redirectUrl, ?string $notice = null): StandaloneTemplateResponse {
		$safeRedirect = $this->safe($redirectUrl);
		$expiresAt = $this->approvalMethod($user, $pending)?->expiresAt($user, $pending) ?? $pending->deadline;
		// Whole minutes: "30 minutes", not "1799 seconds".
		$texts = $this->textsFor($user, $pending, max(60, (int)ceil(($expiresAt - $this->timeFactory->getTime()) / 60) * 60));
		Util::addScript(Application::APP_ID, 'verify');
		return $this->render(self::MODE_WAITING, [
			'title' => $this->l->t('Waiting for an administrator'),
			'lead' => $texts['waitingLead'],
			'why' => $texts['why'],
			'notice' => $notice,
			'expires' => $texts['expires'],
			'hasCode' => $pending->hasMethod(IConfirmationMethod::EMAIL_CODE),
			'codeUrl' => $this->urlGenerator->linkToRoute($this->flow->route('show'), array_filter(['use' => self::MODE_CODE, 'redirect_url' => $safeRedirect])),
			'canRemember' => $this->flow->canRemember(),
			'rememberFor' => TextRenderer::duration($this->knownDevices->duration(), $this->l),
			'warning' => $texts['waitingWarning'],
			'cancelLabel' => $texts['cancel'],
			'statusUrl' => $this->urlGenerator->linkToRoute($this->flow->route('approvalStatus')),
			'pollInterval' => self::POLL_INTERVAL,
			'continueAction' => $this->urlGenerator->linkToRoute($this->flow->route('continueApproval')),
			'cancelAction' => $this->urlGenerator->linkToRoute($this->flow->route('cancelApproval')),
			'redirect_url' => $safeRedirect,
		]);
	}

	/**
	 * @param array<string, mixed> $params
	 */
	public function render(string $mode, array $params): StandaloneTemplateResponse {
		Util::addStyle(Application::APP_ID, 'pages');
		return new StandaloneTemplateResponse(Application::APP_ID, self::TEMPLATE, array_merge([
			'mode' => $mode,
			'logout_url' => $this->urlGenerator->getLogoutUrl(),
			'login_url' => $this->urlGenerator->linkToRoute('core.login.showLoginForm'),
		], $params), 'guest');
	}

	public function secondFactorMethod(IUser $user, StepUpState $pending): ?SecondFactorMethod {
		$method = $this->methodOf($user, $pending, IConfirmationMethod::SECOND_FACTOR);
		return $method instanceof SecondFactorMethod ? $method : null;
	}

	public function approvalMethod(IUser $user, StepUpState $pending): ?AdminApprovalMethod {
		$method = $this->methodOf($user, $pending, IConfirmationMethod::ADMIN_APPROVAL);
		return $method instanceof AdminApprovalMethod ? $method : null;
	}

	public function continue(string $redirectUrl): RedirectResponse {
		return new RedirectResponse($this->redirect->target($redirectUrl, $this->flow->excluded()));
	}

	public function safe(string $redirectUrl): string {
		return LocalRedirect::isSafe($redirectUrl, $this->flow->excluded()) ? $redirectUrl : '';
	}

	/**
	 * @return array{title: string, lead: string, leadCode: string, why: ?string, warning: string, waitingLead: string, waitingWarning: string, expires: string, cancel: string}
	 */
	private function textsFor(IUser $user, StepUpState $pending, int $waitSeconds): array {
		return $this->flow->texts($pending, [
			'masked' => EmailCodes::mask((string)$user->getEMailAddress()),
			'valid' => TextRenderer::duration($this->settings->getInt(GlobalSettings::STEP_UP_CODE_TTL), $this->l),
			'because' => StepUpPolicy::describeAll($pending->policies, $this->l),
			'left' => TextRenderer::duration($waitSeconds, $this->l),
		]);
	}

	/**
	 * A method of the confirmation in progress, while it is still available
	 * for every one of its policies.
	 */
	private function methodOf(IUser $user, StepUpState $pending, string $id): ?IConfirmationMethod {
		if (!$pending->hasMethod($id)) {
			return null;
		}
		$method = $this->policy->method($id);
		if ($method === null) {
			return null;
		}
		foreach ($pending->policies as $policy) {
			$known = StepUpPolicy::tryFrom($policy);
			if ($known === null || !$method->isAvailable($user, $known)) {
				return null;
			}
		}
		return $method;
	}
}
