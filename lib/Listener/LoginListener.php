<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\CredentialUse\CredentialUse;
use OCA\IntrusionDetection\Check\CredentialUse\CredentialUseResolver;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Confirm\UnconfirmedSessions;
use OCA\IntrusionDetection\Guard\DeferredHits;
use OCA\IntrusionDetection\Guard\RequestContext;
use OCA\IntrusionDetection\Login\InteractiveLogin;
use OCA\IntrusionDetection\Login\LoginGate;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\IRequest;
use OCP\User\Events\UserLoggedInEvent;
use OCP\User\Events\UserLoggedInWithCookieEvent;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * The app's one listener for successful logins. It runs the listeners that
 * act on logins in this order, and builds each one only when the login
 * concerns it:
 *
 * 1. {@see StepUpLoginListener}: first, so that a new password it requires
 *    is asked for at once; for a session that comes back (a token or the
 *    remember-me cookie) only while unconfirmed sessions may exist;
 * 2. {@see LoginRecordListener};
 * 3. {@see PayloadLoginListener}, while a guard hit waits for its user
 *    ({@see DeferredHits});
 * 4. {@see BreachedPasswordListener}, for logins with a password;
 * 5. {@see PasswordChangeLoginListener}, except for app passwords and tokens;
 * 6. {@see CredentialUseLoginListener}, while a credential the guard noted
 *    waits for its login;
 * 7. {@see LoginHistoryListener}: after the step-up, so that the row says
 *    how the login was confirmed.
 *
 * Core reports a login for every request with Basic or Bearer
 * credentials. For an app that sends its app password again, the logins
 * per address and the history ask the {@see LoginGate} first: after the
 * app's first request of the hour from an address nothing is built.
 *
 * @template-implements IEventListener<UserLoggedInEvent|UserLoggedInWithCookieEvent>
 */
class LoginListener implements IEventListener {
	public const PRIORITY = Application::LOGIN_PRIORITY;

	public function __construct(
		private readonly Settings $settings,
		private readonly RequestContext $context,
		private readonly RemoteAddressResolver $addresses,
		private readonly LoginGate $gate,
		private readonly IRequest $request,
		private readonly ITimeFactory $timeFactory,
		private readonly ContainerInterface $container,
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
			$listeners = $event instanceof UserLoggedInEvent ? $this->forLogin($event) : $this->forCookie();
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not handle a login', ['exception' => $e]);
			return;
		}
		foreach ($listeners as $class) {
			try {
				$listener = $this->container->get($class);
				if ($listener instanceof IEventListener) {
					$listener->handle($event);
				}
			} catch (\Throwable $e) {
				// One listener that cannot be built must not stop the others, nor the login.
				$this->logger->error('Intrusion detection could not run {listener}', ['listener' => $class, 'exception' => $e]);
			}
		}
	}

	/**
	 * @return list<class-string<IEventListener>>
	 */
	private function forLogin(UserLoggedInEvent $event): array {
		$listeners = [];
		$appClient = false;
		if (!$event->isTokenLogin()) {
			$listeners[] = StepUpLoginListener::class;
		} else {
			// Core takes a Bearer token from the header and an app password from Basic auth;
			// any other token login is a browser session restored from its own token.
			$appClient = str_starts_with($this->request->getHeader('Authorization'), 'Bearer ') || InteractiveLogin::hasBasicCredentials();
			if ($this->resumable()) {
				$listeners[] = StepUpLoginListener::class;
			}
		}
		$recorded = !$appClient || $this->firstOfTheHour($event);
		if ($recorded) {
			$listeners[] = LoginRecordListener::class;
		}
		if (DeferredHits::isPending($this->context)) {
			$listeners[] = PayloadLoginListener::class;
		}
		if (!$event->isTokenLogin()) {
			$listeners[] = BreachedPasswordListener::class;
		}
		if (!$appClient) {
			$listeners[] = PasswordChangeLoginListener::class;
		}
		$use = $this->context->get(CredentialUseResolver::CONTEXT_KEY);
		if ($use instanceof CredentialUse && $use->needsResolution()) {
			$listeners[] = CredentialUseLoginListener::class;
		}
		if ($recorded) {
			$listeners[] = LoginHistoryListener::class;
		}
		return $listeners;
	}

	/**
	 * @return list<class-string<IEventListener>>
	 */
	private function forCookie(): array {
		$listeners = $this->resumable() ? [StepUpLoginListener::class] : [];
		return [...$listeners, PasswordChangeLoginListener::class, LoginHistoryListener::class];
	}

	/**
	 * Whether a returning session could resume a login that was never confirmed.
	 */
	private function resumable(): bool {
		return UnconfirmedSessions::mayExistIn($this->settings, $this->timeFactory->getTime());
	}

	/**
	 * Whether an app's login is the first with its credential from its
	 * address in the hour, or the gate cannot tell (no memory cache).
	 */
	private function firstOfTheHour(UserLoggedInEvent $event): bool {
		$source = $this->addresses->current();
		if ($source === null) {
			return true;
		}
		return $this->gate->isFirst($event->getUser()->getUID(), $source->ipKey, $this->timeFactory->getTime()) !== false;
	}
}
