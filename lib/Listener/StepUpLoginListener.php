<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\IntrusionDetection\Check\Checks\BreachedPassword;
use OCA\IntrusionDetection\Check\Checks\BreachedPasswordDetector;
use OCA\IntrusionDetection\Check\Checks\PasswordSprayingDetector;
use OCA\IntrusionDetection\Check\Checks\RiskyNetworkDetector;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Confirm\LoginContext;
use OCA\IntrusionDetection\Confirm\LoginDetections;
use OCA\IntrusionDetection\Confirm\StepUpReasons;
use OCA\IntrusionDetection\Confirm\StepUpService;
use OCA\IntrusionDetection\Confirm\UnconfirmedSessions;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Login\InteractiveLogin;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\IRequest;
use OCP\ISession;
use OCP\User\Events\UserLoggedInEvent;
use OCP\User\Events\UserLoggedInWithCookieEvent;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * Decides at every successful password login whether it needs extra
 * confirmation (concept sections 11.5 and 12.2, steps 4 to 7):
 *
 * - a successful login with a sprayed password is reported
 *   ({@see PasswordSprayingDetector::detectSuccess()});
 * - a login from a hosting or Tor network is reported
 *   ({@see RiskyNetworkDetector::detectLogin()});
 * - the breach check runs, when it is on and due;
 * - the step-up reasons are collected and {@see StepUpService} decides.
 *
 * Only logins with the account's password count: through the login form,
 * or from apps and scripts that send it (Basic auth). App passwords and
 * tokens never need it. A session that comes back through its remember-me
 * cookie or its session token is checked against the unconfirmed sessions,
 * so that a login that was never confirmed cannot be resumed.
 *
 * It runs before the app's other login listeners (PRIORITY), so that a new
 * password required here is picked up by the forced password change at
 * once. Failures are logged and never break a login.
 *
 * @template-implements IEventListener<UserLoggedInEvent|UserLoggedInWithCookieEvent>
 */
class StepUpLoginListener implements IEventListener {
	public const PRIORITY = 10;
	/** Core's cookie with the id of the session a remember-me login renews */
	public const SESSION_ID_COOKIE = 'nc_session_id';

	public function __construct(
		private readonly Settings $settings,
		private readonly InteractiveLogin $interactive,
		private readonly RemoteAddressResolver $addresses,
		private readonly Fingerprinter $fingerprinter,
		private readonly FlaggedSources $flags,
		private readonly StepUpReasons $reasons,
		private readonly UnconfirmedSessions $unconfirmed,
		private readonly IRequest $request,
		private readonly ISession $session,
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
			if ($event instanceof UserLoggedInWithCookieEvent) {
				$this->resumed($event->getUser()->getUID(), $this->request->getCookie(self::SESSION_ID_COOKIE), true);
				return;
			}
			if ($event->isTokenLogin()) {
				if (!$this->hasCredentialHeader()) {
					// A browser session restored from its token: same session id.
					$this->resumed($event->getUser()->getUID(), $this->sessionId(), false);
				}
				return;
			}
			$this->passwordLogin($event);
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not decide whether a login needs extra confirmation', ['exception' => $e]);
		}
	}

	private function passwordLogin(UserLoggedInEvent $event): void {
		$password = $event->getPassword();
		if ($password === null || $password === '') {
			return;
		}
		$interactive = $this->interactive->isPasswordLogin($event);
		if (!$interactive && !$this->isBasicAuth()) {
			// Single sign-on and other logins that do not involve a person typing the password.
			return;
		}
		$source = $this->addresses->current();
		if ($source !== null && $this->addresses->isBypassListed($source)) {
			return;
		}
		$user = $event->getUser();
		$userAgent = $this->request->getHeader('User-Agent');
		$candidates = array_map('bin2hex', $this->fingerprinter->passwordCandidates($password));
		$login = new LoginContext($user, $source, $interactive, $userAgent, $candidates, $this->flags->isPasswordFlagged($candidates));

		$detections = [];
		try {
			$sprayed = $this->container->get(PasswordSprayingDetector::class)->detectSuccess($login);
			if ($sprayed !== null) {
				$detections[] = $sprayed->getId();
			}
			$risky = $this->container->get(RiskyNetworkDetector::class)->detectLogin($login);
			if ($risky !== null) {
				$detections[] = $risky->getId();
			}
			if ($interactive && $this->settings->modeState(BreachedPassword::ID)->runs()) {
				// The check keeps its result for this request, so its own listener does not ask again.
				$this->container->get(BreachedPasswordDetector::class)->checkAtLogin($user, $password, $userAgent);
			}
		} catch (\Throwable $e) {
			// The decision below must still happen.
			$this->logger->error('Intrusion detection could not check a password login', ['exception' => $e]);
		}

		$stepUps = $this->container->get(StepUpService::class);
		$linker = $this->container->get(LoginDetections::class);
		if (!$stepUps instanceof StepUpService || !$linker instanceof LoginDetections) {
			return;
		}
		[, $recorded] = $stepUps->atLogin($login, $this->reasons->collect($login));
		$linker->await($user->getUID(), [...$detections, ...$recorded]);
	}

	/**
	 * @param bool $renewed whether core gave the session a new id (remember-me)
	 */
	private function resumed(string $uid, ?string $sessionId, bool $renewed): void {
		if ($sessionId === null || $sessionId === '' || !$this->unconfirmed->mayExist()) {
			return;
		}
		$owner = $this->unconfirmed->accountOf($sessionId);
		if ($owner === null || $owner !== $uid) {
			return;
		}
		$this->container->get(StepUpService::class)->resumed($uid, $renewed ? $sessionId : null);
	}

	private function hasCredentialHeader(): bool {
		return $this->request->getHeader('Authorization') !== '' || $this->request->getHeader('PHP_AUTH_USER') !== '';
	}

	private function isBasicAuth(): bool {
		return $this->request->getHeader('PHP_AUTH_USER') !== ''
			|| str_starts_with(strtolower(trim($this->request->getHeader('Authorization'))), 'basic ');
	}

	private function sessionId(): ?string {
		try {
			return $this->session->getId();
		} catch (\Throwable) {
			return null;
		}
	}
}
