<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\BreachedPassword;
use OCA\IntrusionDetection\Check\Checks\BreachedPasswordDetector;
use OCA\IntrusionDetection\Check\Checks\PasswordSprayingDetector;
use OCA\IntrusionDetection\Check\Checks\RiskyNetworkDetector;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Confirm\LoginContext;
use OCA\IntrusionDetection\Confirm\LoginDetections;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Confirm\StepUpReasons;
use OCA\IntrusionDetection\Confirm\StepUpService;
use OCA\IntrusionDetection\Confirm\UnconfirmedSessions;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Login\InteractiveLogin;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\ICache;
use OCP\ICacheFactory;
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
 * or from apps and scripts that send it (Basic auth); a password login of
 * any other kind is treated like the login form ({@see InteractiveLogin}).
 * Basic auth is an app whatever cookies it sends: no confirmation is ever
 * started for it ({@see StepUpService}).
 * App passwords and tokens never need it. A session that comes back through its remember-me
 * cookie or its session token is checked against the unconfirmed sessions,
 * so that a login that was never confirmed cannot be resumed.
 *
 * An app or script that sends the password does so on every request. Its
 * decision is repeated for CLIENT_DECISION_TTL seconds per account,
 * password and address when a memory cache exists, so that the checks run
 * once, not per request.
 *
 * It runs before the app's other login listeners ({@see LoginListener}),
 * so that a new password required here is picked up by the forced password
 * change at once. Failures are logged and never break a login.
 *
 * @template-implements IEventListener<UserLoggedInEvent|UserLoggedInWithCookieEvent>
 */
class StepUpLoginListener implements IEventListener {
	/** Core's cookie with the id of the session a remember-me login renews */
	public const SESSION_ID_COOKIE = 'nc_session_id';
	/** How long the decision about an app sending the password is repeated */
	public const CLIENT_DECISION_TTL = 60;

	private ?ICache $cache = null;
	private bool $cacheInitialised = false;

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
		private readonly ICacheFactory $cacheFactory,
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
				// A browser session restored from its token keeps its session id; for app
				// passwords and Bearer tokens the id is new and matches nothing.
				$this->resumed($event->getUser()->getUID(), $this->sessionId(), false);
				return;
			}
			$this->passwordLogin($event);
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not decide whether a login needs extra confirmation', ['exception' => $e]);
		}
	}

	private function passwordLogin(UserLoggedInEvent $event): void {
		$kind = $this->interactive->kind($event);
		$password = $event->getPassword();
		if ($kind === null || $password === null) {
			return;
		}
		$interactive = $kind !== InteractiveLogin::CLIENT;
		$source = $this->addresses->current();
		if ($source !== null && $this->addresses->isBypassListed($source)) {
			return;
		}
		$user = $event->getUser();
		$userAgent = $this->request->getHeader('User-Agent');
		$candidates = array_map('bin2hex', $this->fingerprinter->passwordCandidates($password));
		$clientKey = $interactive ? null : self::clientKey($user->getUID(), $candidates, $source);
		if ($clientKey !== null && $this->repeatClientDecision($clientKey, $user->getUID(), $source)) {
			return;
		}
		$login = new LoginContext($user, $source, $interactive, $userAgent, $candidates, $this->flags->loginFlags($source, $candidates));

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
		$policies = $this->reasons->collect($login);
		[$outcome, $recorded] = $stepUps->atLogin($login, $policies);
		$linker->await($user->getUID(), [...$detections, ...$recorded]);
		if ($clientKey !== null && in_array($outcome, StepUpService::REPEATABLE, true)) {
			$this->clientCache()?->set($clientKey, [
				'outcome' => $outcome,
				'policies' => array_map(static fn (StepUpPolicy $p): string => $p->value, $policies),
			], self::CLIENT_DECISION_TTL);
		}
	}

	/**
	 * An app sending the password repeats its decision for a while, without
	 * the checks, the reasons and their queries on every request.
	 *
	 * @return bool whether a decision was repeated
	 */
	private function repeatClientDecision(string $key, string $uid, ?SourceKey $source): bool {
		$cached = $this->clientCache()?->get($key);
		if (!is_array($cached) || !in_array($cached['outcome'] ?? null, StepUpService::REPEATABLE, true) || !is_array($cached['policies'] ?? null)) {
			return false;
		}
		$stepUps = $this->container->get(StepUpService::class);
		if (!$stepUps instanceof StepUpService) {
			return false;
		}
		/** @var StepUpService::NONE|StepUpService::REFUSED_CLIENT|StepUpService::ALLOWED $outcome */
		$outcome = $cached['outcome'];
		$stepUps->repeatClient($uid, $source, $outcome, array_values(array_filter($cached['policies'], 'is_string')));
		return true;
	}

	/**
	 * Per account, password (its daily fingerprint, never the password) and address.
	 *
	 * @param list<string> $candidates
	 */
	private static function clientKey(string $uid, array $candidates, ?SourceKey $source): ?string {
		if ($candidates === []) {
			return null;
		}
		return 'stepup_client:' . hash('sha256', $uid . "\0" . $candidates[0] . "\0" . ($source?->ipKey ?? '-'));
	}

	private function clientCache(): ?ICache {
		if (!$this->cacheInitialised) {
			$this->cacheInitialised = true;
			if ($this->cacheFactory->isAvailable()) {
				$this->cache = $this->cacheFactory->createDistributed(Application::APP_ID);
			} elseif ($this->cacheFactory->isLocalCacheAvailable()) {
				$this->cache = $this->cacheFactory->createLocal(Application::APP_ID);
			}
		}
		return $this->cache;
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

	private function sessionId(): ?string {
		try {
			return $this->session->getId();
		} catch (\Throwable) {
			return null;
		}
	}
}
