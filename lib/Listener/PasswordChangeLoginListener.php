<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Login\LoginClassifier;
use OCA\IntrusionDetection\Response\PasswordChangeService;
use OCA\IntrusionDetection\SessionState\Rules\PasswordChangeRule;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
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
		private readonly AppSettings $settings,
		private readonly PasswordChangeService $passwords,
		private readonly SessionState $state,
		private readonly LoginClassifier $classifier,
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
			$mode = PasswordChangeRule::modeFor($this->classifier->classify($event));
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
}
