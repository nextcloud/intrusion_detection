<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\KnownDevice\KnownDevices;
use OCA\IntrusionDetection\Login\InteractiveLogin;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Notification\LoginNotices;
use OCP\Authentication\TwoFactorAuth\TwoFactorProviderChallengePassed;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\IRequest;
use OCP\User\Events\UserLoggedInEvent;
use OCP\User\Events\UserLoggedInWithCookieEvent;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * Writes the login history at every successful login (concept section
 * 12.2, step 2), recognises the known device of interactive logins (step
 * 3), and marks the session for the security notice of users without email
 * (section 11.1). It runs after the step-up listener, so the row says how
 * the login was confirmed.
 *
 * A browser session restored from its session token is the same session,
 * not a new login, and is not recorded. Failures are logged and never
 * break a login.
 *
 * @template-implements IEventListener<UserLoggedInEvent|UserLoggedInWithCookieEvent|TwoFactorProviderChallengePassed>
 */
class LoginHistoryListener implements IEventListener {
	public function __construct(
		private readonly Settings $settings,
		private readonly InteractiveLogin $interactive,
		private readonly RemoteAddressResolver $addresses,
		private readonly IRequest $request,
		private readonly ContainerInterface $container,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function handle(Event $event): void {
		if (!$event instanceof UserLoggedInEvent && !$event instanceof UserLoggedInWithCookieEvent && !$event instanceof TwoFactorProviderChallengePassed) {
			return;
		}
		try {
			if (!$this->settings->isEnabled()) {
				return;
			}
			if ($event instanceof TwoFactorProviderChallengePassed) {
				$this->container->get(LoginHistory::class)->secondFactorPassed($event->getUser()->getUID());
				return;
			}
			[$method, $browser] = $event instanceof UserLoggedInWithCookieEvent ? [LoginHistory::METHOD_COOKIE, true] : $this->method($event);
			if ($method === null) {
				return;
			}
			$source = $this->addresses->current();
			if ($source !== null && $this->addresses->isBypassListed($source)) {
				return;
			}
			$uid = $event->getUser()->getUID();
			$interactive = $method === LoginHistory::METHOD_PASSWORD || $method === LoginHistory::METHOD_SSO;
			$devices = $this->container->get(KnownDevices::class);
			$device = $interactive ? $devices->recognise($uid) : null;
			if ($device !== null) {
				$devices->used($device);
			}
			$this->container->get(LoginHistory::class)->record($uid, $method, $source, $this->request->getHeader('User-Agent'), $device, $browser);
			if ($interactive) {
				$this->container->get(LoginNotices::class)->atLogin($uid, $device);
			}
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not record a login', ['exception' => $e]);
		}
	}

	/**
	 * @return array{0: ?LoginHistory::METHOD_*, 1: bool} how the account logged in (null: not a new login), and whether it is a browser session
	 */
	private function method(UserLoggedInEvent $event): array {
		if ($event->isTokenLogin()) {
			if (str_starts_with($this->request->getHeader('Authorization'), 'Bearer ')) {
				return [LoginHistory::METHOD_TOKEN, false];
			}
			// Otherwise core restored a browser session from its token, unless Basic auth carried an app password.
			return InteractiveLogin::hasBasicCredentials() ? [LoginHistory::METHOD_APP_PASSWORD, false] : [null, false];
		}
		return match ($this->interactive->kind($event)) {
			InteractiveLogin::FORM => [LoginHistory::METHOD_PASSWORD, true],
			InteractiveLogin::CLIENT => [LoginHistory::METHOD_CLIENT_PASSWORD, false],
			default => [LoginHistory::METHOD_SSO, true],
		};
	}
}
