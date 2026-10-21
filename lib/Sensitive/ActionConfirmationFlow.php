<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Sensitive;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\StepUpFailed;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Confirm\IConfirmationFlow;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCA\IntrusionDetection\Explain\TextRenderer;
use OCA\IntrusionDetection\Http\LocalRedirect;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\Http\Response;
use OCP\IL10N;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\IUserSession;

/**
 * Confirming a sensitive action on the confirm page (concept section
 * 11.13): the confirmation in progress is kept apart from a login's step-up
 * ({@see SensitiveConfirmations}). Nothing is remembered; too many wrong
 * codes or a rejection end the session; when nobody decides in time, or the
 * user gives up, nothing happens but the confirmation ending.
 */
class ActionConfirmationFlow implements IConfirmationFlow {
	/** Never continued to: the confirm and verify pages */
	public const EXCLUDED = ['/apps/' . Application::APP_ID . '/confirm', '/apps/' . Application::APP_ID . '/verify'];
	/** Reasons of the page where a session ends whose action was not confirmed */
	public const ENDED_ATTEMPTS = 'action_attempts';
	public const ENDED_REJECTED = 'action_rejected';

	public function __construct(
		private readonly SensitiveConfirmations $confirmations,
		private readonly SensitiveSession $sensitive,
		private readonly SessionState $state,
		private readonly IUserSession $userSession,
		private readonly Settings $settings,
		private readonly LocalRedirect $redirect,
		private readonly IURLGenerator $urlGenerator,
		private readonly IL10N $l,
	) {
	}

	#[\Override]
	public function pending(IUser $user): ?StepUpState {
		return $this->confirmations->current($user);
	}

	#[\Override]
	public function save(StepUpState $pending): void {
		$this->confirmations->save($pending);
	}

	#[\Override]
	public function complete(IUser $user, StepUpState $pending, string $method, string $remember): void {
		$this->confirmations->complete($pending, $method);
	}

	#[\Override]
	public function fail(StepUpState $pending, string $rule): Response {
		if ($rule === StepUpFailed::RULE_TIMEOUT) {
			// Nobody decided in time: nothing points to an attack; start again.
			$this->confirmations->abandon($pending);
			return new RedirectResponse($this->urlGenerator->linkToRoute($this->route('show')));
		}
		$rejected = $rule === StepUpFailed::RULE_REJECTED;
		$this->confirmations->fail($pending, $rejected ? StepUpFailed::RULE_REJECTED : StepUpFailed::RULE_ATTEMPTS);
		return new RedirectResponse($this->urlGenerator->linkToRoute(Application::APP_ID . '.Verify.ended', [
			'reason' => $rejected ? self::ENDED_REJECTED : self::ENDED_ATTEMPTS,
		]));
	}

	#[\Override]
	public function giveUp(IUser $user, StepUpState $pending, string $redirectUrl): Response {
		$this->confirmations->abandon($pending);
		return new RedirectResponse($this->redirect->target($redirectUrl, self::EXCLUDED));
	}

	#[\Override]
	public function route(string $action): string {
		return Application::APP_ID . '.Confirm.' . $action;
	}

	#[\Override]
	public function excluded(): array {
		return self::EXCLUDED;
	}

	#[\Override]
	public function canRemember(): bool {
		return false;
	}

	#[\Override]
	public function escape(string $redirectUrl): array {
		return ['url' => $this->redirect->target($redirectUrl, self::EXCLUDED), 'label' => $this->l->t('Cancel')];
	}

	#[\Override]
	public function texts(StepUpState $pending, array $values): array {
		$ttl = TextRenderer::duration($this->settings->getInt(GlobalSettings::SENSITIVE_CONFIRM_TTL), $this->l);
		return [
			'title' => $this->l->t('Confirm it\'s you'),
			'lead' => $this->l->t('To do this, we need to confirm it\'s you. Afterwards you go back and do it again; for %s, nothing else is asked.', [$ttl]),
			'leadCode' => $this->l->t('To do this, we need to confirm it\'s you. We sent a 6-digit code to %1$s. It is valid for %2$s.', [$values['masked'], $values['valid']]),
			'why' => $this->why(),
			'warning' => $this->l->t('If you did not just try to change something, someone else may be using your account. Do not enter the code anywhere; log out and change your password.'),
			'waitingLead' => $this->l->t('An administrator needs to confirm this. You can keep this page open; it continues automatically once approved.'),
			'waitingWarning' => $this->l->t('If you did not just try to change something, someone else may be using your account. Cancel, log out and change your password.'),
			'expires' => $this->l->t('If nobody decides within %s, you can try again.', [$values['left']]),
			'cancel' => $this->l->t('Cancel'),
		];
	}

	/**
	 * Why this session must confirm, in the user's words.
	 */
	private function why(): ?string {
		$user = $this->userSession->getUser();
		return match ($user === null ? null : $this->sensitive->riskReason($this->state, $user->getUID())) {
			SensitiveSession::REASON_LOCKDOWN => $this->l->t('Your administrator turned on extra security checks for everyone.'),
			SensitiveSession::REASON_UNCONFIRMED_LOGIN => $this->l->t('Your login could not be confirmed, so changes like this need it now.'),
			SensitiveSession::REASON_DETECTION => $this->l->t('Nextcloud noticed unusual activity in this session.'),
			SensitiveSession::REASON_ADMIN => $this->l->t('Administrators confirm important changes when they last confirmed it\'s them a while ago.'),
			default => null,
		};
	}
}
