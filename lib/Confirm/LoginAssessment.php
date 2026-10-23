<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Login\CoreSession;
use OCA\IntrusionDetection\Login\LoginContext;
use OCA\IntrusionDetection\Login\LoginKind;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\Signal\InteractivePasswordLogin;
use OCA\IntrusionDetection\Signal\SignalDispatcher;
use OCA\IntrusionDetection\Signal\SuccessfulLogin;
use OCP\IRequest;
use OCP\IUser;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * Decides at every successful password login whether it needs extra
 * confirmation (concept sections 11.5 and 12.2, steps 4 to 7):
 *
 * - the login is judged ({@see SuccessfulLogin}): a sprayed password and a
 *   hosting or Tor network are reported;
 * - the breach check runs on a password a person typed, when it is on and
 *   due ({@see InteractivePasswordLogin});
 * - the step-up reasons are collected and {@see LoginConfirmations} decides.
 *
 * Basic auth is an app whatever cookies it sends: no confirmation is ever
 * started for it. A session that comes back through its remember-me
 * cookie or its session token is checked against the unconfirmed
 * sessions, so that a login that was never confirmed cannot be resumed.
 *
 * An app or script that sends the password does so on every request. Its
 * decision is repeated for CLIENT_DECISION_TTL seconds per account,
 * password and address when a memory cache exists, so that the checks run
 * once, not per request.
 */
class LoginAssessment {
	/** The namespace of its memory cache in {@see Caches} */
	public const CACHE = 'step-up-clients';
	/** Core's cookie with the id of the session a remember-me login renews */
	public const SESSION_ID_COOKIE = 'nc_session_id';
	/** How long the decision about an app sending the password is repeated */
	public const CLIENT_DECISION_TTL = 60;
	/** The decisions about an app sending the password that may be repeated */
	private const REPEATABLE = [ConfirmationStatus::None, ConfirmationStatus::RefusedClient, ConfirmationStatus::AllowedUnconfirmed];

	public function __construct(
		private readonly Fingerprinter $fingerprinter,
		private readonly FlaggedSources $flags,
		private readonly StepUpReasons $reasons,
		private readonly UnconfirmedSessions $unconfirmed,
		private readonly CoreSession $coreSession,
		private readonly IRequest $request,
		private readonly ContainerInterface $container,
		private readonly Caches $caches,
		private readonly LoggerInterface $logger,
	) {
	}

	/**
	 * A login with the account's password, from a person ($interactive) or
	 * from an app or script that sent it with Basic auth.
	 */
	public function passwordLogin(IUser $user, #[\SensitiveParameter] string $password, bool $interactive, ?SourceKey $source, ?string $userAgent): LoginConfirmation {
		$candidates = array_map('bin2hex', $this->fingerprinter->passwordCandidates($password));
		$clientKey = $interactive ? null : $this->clientKey($user->getUID(), $candidates, $source);
		$repeated = $clientKey === null ? null : $this->repeatClientDecision($clientKey, $user->getUID(), $source);
		if ($repeated !== null) {
			return $repeated;
		}
		$login = new LoginContext($user, $source, $interactive, $userAgent, $candidates, $this->flags->loginFlags($source, $candidates));

		$detections = [];
		try {
			$dispatcher = $this->container->get(SignalDispatcher::class);
			foreach ($dispatcher->dispatch(new SuccessfulLogin($login))->detections as $detection) {
				$detections[] = $detection->getId();
			}
			if ($interactive) {
				// The check remembers the account for this request, so the breach step does not ask again.
				$dispatcher->dispatch(new InteractivePasswordLogin($user, $password, $userAgent));
			}
		} catch (\Throwable $e) {
			// The decision below must still happen.
			$this->logger->error('Intrusion detection could not check a password login', ['exception' => $e]);
		}

		$policies = $this->reasons->collect($login);
		[$confirmation, $recorded] = $this->stepUps()->atLogin($login, $policies);
		$this->linker()->await($user->getUID(), [...$detections, ...$recorded]);
		if ($clientKey !== null && in_array($confirmation->status, self::REPEATABLE, true)) {
			$this->caches->shared(self::CACHE)?->set($clientKey, [
				'outcome' => $confirmation->status->value,
				'policies' => array_map(static fn (StepUpPolicy $p): string => $p->value, $policies),
			], self::CLIENT_DECISION_TTL);
		}
		return $confirmation;
	}

	/**
	 * A session that came back with a token or its remember-me cookie. One
	 * whose login was never confirmed is marked, so that the session rule
	 * ends it on its first request.
	 */
	public function returning(string $uid, LoginKind $kind): LoginConfirmation {
		// Core renews the session of a remember-me login; a browser session restored
		// from its token keeps its id, and app passwords and Bearer tokens get a new one.
		$renewed = $kind === LoginKind::RememberMeCookie;
		$sessionId = $renewed ? $this->request->getCookie(self::SESSION_ID_COOKIE) : $this->coreSession->sessionId();
		if ($sessionId === null || $sessionId === '' || !$this->unconfirmed->mayExist()) {
			return LoginConfirmation::none($uid);
		}
		if ($this->unconfirmed->accountOf($sessionId) !== $uid) {
			return LoginConfirmation::none($uid);
		}
		return $this->stepUps()->resumed($uid, $renewed ? $sessionId : null);
	}

	/**
	 * An app sending the password repeats its decision for a while, without
	 * the checks, the reasons and their queries on every request.
	 */
	private function repeatClientDecision(string $key, string $uid, ?SourceKey $source): ?LoginConfirmation {
		$cached = $this->caches->shared(self::CACHE)?->get($key);
		$status = is_array($cached) && is_string($cached['outcome'] ?? null) ? ConfirmationStatus::tryFrom($cached['outcome']) : null;
		if ($status === null || !in_array($status, self::REPEATABLE, true) || !is_array($cached['policies'] ?? null)) {
			return null;
		}
		return $this->stepUps()->repeatClient($uid, $source, $status, array_values(array_filter($cached['policies'], 'is_string')));
	}

	/**
	 * Built only when a login needs it.
	 */
	private function stepUps(): LoginConfirmations {
		$stepUps = $this->container->get(LoginConfirmations::class);
		return $stepUps instanceof LoginConfirmations ? $stepUps : throw new \LogicException('No step-up service');
	}

	private function linker(): LoginDetections {
		$linker = $this->container->get(LoginDetections::class);
		return $linker instanceof LoginDetections ? $linker : throw new \LogicException('No login detections');
	}

	/**
	 * Per account, password (its daily fingerprint, never the password) and address.
	 *
	 * @param list<string> $candidates
	 */
	private function clientKey(string $uid, array $candidates, ?SourceKey $source): ?string {
		if ($candidates === []) {
			return null;
		}
		return 'stepup_client:' . $this->fingerprinter->lookup($uid, $candidates[0], $source?->ipKey ?? '-');
	}
}
