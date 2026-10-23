<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Confirm\IConfirmationMethod;
use OCA\IntrusionDetection\Confirm\SessionConfirmation;
use OCA\IntrusionDetection\KnownDevice\KnownDevices;
use OCA\IntrusionDetection\Login\LoginClassifier;
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
		private readonly AppSettings $settings,
		private readonly LoginClassifier $classifier,
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
			$kind = $this->classifier->classify($event);
			$method = LoginHistory::methodOf($kind);
			if ($method === null) {
				return;
			}
			$source = $this->addresses->current();
			if ($source !== null && $this->addresses->isBypassListed($source)) {
				return;
			}
			$uid = $event->getUser()->getUID();
			$interactive = $kind->isInteractive();
			$device = null;
			if ($interactive) {
				$devices = $this->container->get(KnownDevices::class);
				$device = $devices->recognise($uid);
				if ($device !== null) {
					$devices->used($device);
					$this->container->get(SessionConfirmation::class)->proved($uid, IConfirmationMethod::KNOWN_DEVICE);
				}
			}
			$this->container->get(LoginHistory::class)->record($uid, $method, $source, $this->request->getHeader('User-Agent'), $device, $kind->isBrowser());
			if ($interactive) {
				$this->container->get(LoginNotices::class)->atLogin($uid, $device);
			}
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not record a login', ['exception' => $e]);
		}
	}
}
