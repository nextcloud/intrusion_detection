<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Login\InteractiveLogin;
use OCA\IntrusionDetection\Response\PasswordChangeService;
use OCA\IntrusionDetection\SessionState\Rules\PasswordChangeRule;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\IRequest;
use OCP\User\Events\UserLoggedInEvent;
use OCP\User\Events\UserLoggedInWithCookieEvent;
use Psr\Log\LoggerInterface;

/**
 * At each login of an account that must choose a new password, marks the
 * session for {@see PasswordChangeRule}:
 *
 * - browser logins (the login form, single sign-on, a remembered login, a
 *   browser session restored from its token) are sent to the password page;
 * - logins with the password over Basic auth (apps and scripts, which
 *   cannot open a page) are refused;
 * - logins with an app password or token are left alone: the attacker
 *   guessed the password, not the app passwords.
 *
 * An account whose password is managed outside Nextcloud is not marked;
 * the administrators are asked to reset it instead. Failures are logged and
 * never break the login.
 *
 * @template-implements IEventListener<UserLoggedInEvent|UserLoggedInWithCookieEvent>
 */
class PasswordChangeLoginListener implements IEventListener {
	public function __construct(
		private readonly Settings $settings,
		private readonly PasswordChangeService $passwords,
		private readonly SessionState $state,
		private readonly IRequest $request,
		private readonly InteractiveLogin $interactive,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function handle(Event $event): void {
		if (!$event instanceof UserLoggedInEvent && !$event instanceof UserLoggedInWithCookieEvent) {
			return;
		}
		try {
			if (!$this->settings->isEnabled()) {
				return;
			}
			$mode = $this->mode($event);
			if ($mode === null) {
				return;
			}
			$user = $event->getUser();
			$since = $this->passwords->requiredSince($user->getUID());
			if ($since === null) {
				return;
			}
			if (!$user->canChangePassword()) {
				$this->passwords->external($user);
				return;
			}
			$this->state->set(SessionState::PASSWORD_CHANGE, ['uid' => $user->getUID(), 'mode' => $mode, 'since' => $since]);
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not check for a required password change at login', ['exception' => $e]);
		}
	}

	/**
	 * @return ?string the rule's mode for this login, or null for app passwords and tokens
	 */
	private function mode(UserLoggedInEvent|UserLoggedInWithCookieEvent $event): ?string {
		if ($event instanceof UserLoggedInWithCookieEvent) {
			return PasswordChangeRule::MODE_REDIRECT;
		}
		if ($event->isTokenLogin()) {
			// Core takes a Bearer token from the header and an app password from Basic auth;
			// any other token login is a browser session restored from its own token.
			$bearer = str_starts_with($this->request->getHeader('Authorization'), 'Bearer ');
			return ($bearer || InteractiveLogin::hasBasicCredentials()) ? null : PasswordChangeRule::MODE_REDIRECT;
		}
		return $this->interactive->kind($event) === InteractiveLogin::CLIENT ? PasswordChangeRule::MODE_REFUSE : PasswordChangeRule::MODE_REDIRECT;
	}
}
