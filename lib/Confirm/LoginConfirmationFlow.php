<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\KnownDevice\KnownDevices;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\Http\Response;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IURLGenerator;
use OCP\IUser;

/**
 * Confirming a login on the verify page (concept section 11.5): the
 * confirmation in progress is the session's step-up ({@see StepUpService}).
 * After confirming, the browser may be remembered; a failure ends the
 * login; giving up returns to the login page.
 */
class LoginConfirmationFlow implements IConfirmationFlow {
	/** Never continued to: the verify pages themselves */
	public const EXCLUDED = ['/apps/' . Application::APP_ID . '/verify'];

	public function __construct(
		private readonly StepUpService $stepUps,
		private readonly KnownDevices $knownDevices,
		private readonly RemoteAddressResolver $addresses,
		private readonly IRequest $request,
		private readonly IURLGenerator $urlGenerator,
		private readonly IL10N $l,
	) {
	}

	#[\Override]
	public function pending(IUser $user): ?StepUpState {
		return $this->stepUps->current();
	}

	#[\Override]
	public function save(StepUpState $pending): void {
		$this->stepUps->save($pending);
	}

	#[\Override]
	public function complete(IUser $user, StepUpState $pending, string $method, string $remember): void {
		$this->stepUps->complete($pending, $method);
		if ($remember === '1') {
			$this->knownDevices->remember($user, $this->addresses->current(), $this->request->getHeader('User-Agent'));
		}
	}

	#[\Override]
	public function fail(StepUpState $pending, string $rule): Response {
		$this->stepUps->fail($pending, $rule);
		return new RedirectResponse($this->urlGenerator->linkToRoute($this->route('ended'), ['reason' => $rule]));
	}

	#[\Override]
	public function giveUp(IUser $user, StepUpState $pending, string $redirectUrl): Response {
		$this->stepUps->abandon($pending);
		return new RedirectResponse($this->urlGenerator->linkToRoute('core.login.showLoginForm'));
	}

	#[\Override]
	public function route(string $action): string {
		return Application::APP_ID . '.Verify.' . $action;
	}

	#[\Override]
	public function excluded(): array {
		return self::EXCLUDED;
	}

	#[\Override]
	public function canRemember(): bool {
		return $this->knownDevices->isEnabled();
	}

	#[\Override]
	public function escape(string $redirectUrl): array {
		return ['url' => $this->urlGenerator->getLogoutUrl(), 'label' => $this->l->t('Log out')];
	}

	#[\Override]
	public function texts(StepUpState $pending, array $values): array {
		return [
			'title' => $this->l->t('Confirm it\'s you'),
			'lead' => $this->l->t('We noticed unusual activity around your login, so we need to confirm it\'s you.'),
			'leadCode' => $this->l->t('We noticed unusual activity around your login, so we need to confirm it\'s you. We sent a 6-digit code to %1$s. It is valid for %2$s.', [$values['masked'], $values['valid']]),
			'why' => $values['because'] === '' ? null : $this->l->t('This login needs it because %s.', [$values['because']]),
			'warning' => $this->l->t('If you did not just log in, someone knows your password. Do not enter the code anywhere; log out and change your password.'),
			'waitingLead' => $this->l->t('An administrator needs to confirm this login. You can keep this page open; it continues automatically once approved.'),
			'waitingWarning' => $this->l->t('If you did not just log in, someone knows your password. Cancel this login, then change your password.'),
			'expires' => $this->l->t('If nobody decides within %s, the login ends and you can try again.', [$values['left']]),
			'cancel' => $this->l->t('Cancel this login'),
		];
	}
}
