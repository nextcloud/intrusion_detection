<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\TokenConcurrentUse;

use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Login\CoreSession;
use OCA\IntrusionDetection\Login\RequestContext;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Signal\SignalDispatcher;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IConfig;
use OCP\IRequest;
use OCP\IUser;
use OCP\IUserSession;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * After authentication: decides whether the credential the guard tracked
 * is the one that logged the request in, and records the detection of a
 * pending switch only then.
 *
 * It runs at the first of: a login in this request (UserLoggedInEvent,
 * which can only decide password logins: core stores the session's app
 * password after the event), the session-state rules (every AppFramework
 * and WebDAV request of a logged-in user), and the end of the request.
 *
 * Verification, with the credential read from the request again:
 * - Bearer, and Basic with an app password: the session's app password is
 *   that secret (core sets it for every token login and keeps it in a
 *   reused session).
 * - Basic with the login password: a password login with that name
 *   happened in this request.
 * - The session cookie: its value is the id of the logged-in session. A
 *   session that was replaced during the request (a login form) is not the
 *   one the cookie named.
 *
 * When a request sent an Authorization header but its session cookie
 * logged it in (core ignores the header for a logged-in session), the
 * cookie is tracked instead, so a stolen session cannot hide behind a made
 * up header. Clients that send their app password together with the
 * session cookie are verified by the first rule and cost nothing more.
 */
class CredentialUseResolver {
	public const CONTEXT_KEY = TokenConcurrentUse::ID . '.use';

	public function __construct(
		private readonly RequestContext $context,
		private readonly IRequest $request,
		private readonly IConfig $config,
		private readonly ContainerInterface $container,
		private readonly LoggerInterface $logger,
	) {
	}

	/**
	 * What the guard noted for this request, while something is left to decide.
	 */
	public function pending(): ?CredentialUse {
		$use = $this->context->get(self::CONTEXT_KEY);
		return $use instanceof CredentialUse && $use->needsResolution() ? $use : null;
	}

	/**
	 * A login succeeded in this request.
	 */
	public function loggedIn(IUser $user, string $loginName, bool $tokenLogin): void {
		$use = $this->pending();
		if ($use === null) {
			return;
		}
		if (!$tokenLogin) {
			$use->passwordLoginUid = $user->getUID();
			$use->passwordLoginName = $loginName;
		}
		$this->resolve(false);
	}

	/**
	 * @param bool $final whether authentication is over, so that what cannot
	 *                    be verified now never will be
	 */
	public function resolve(bool $final): void {
		$use = $this->pending();
		if ($use === null) {
			return;
		}
		try {
			$this->decide($use, $final);
		} catch (\Throwable $e) {
			$use->resolved = true;
			$this->logger->error('Intrusion detection could not record a credential used from two networks', ['exception' => $e]);
		}
	}

	private function decide(CredentialUse $use, bool $final): void {
		$userSession = $this->container->get(IUserSession::class);
		$user = $userSession->getUser();
		if ($user === null || !$userSession->isLoggedIn()) {
			// A credential that never logs in never becomes a detection.
			$use->resolved = $use->resolved || $final;
			return;
		}
		$credential = PresentedCredential::fromRequest($this->request, $this->sessionCookieName());
		if ($credential === null || $credential->scheme !== $use->scheme) {
			$use->resolved = true;
			return;
		}
		$session = $this->container->get(CoreSession::class);
		$appPassword = $session->appPassword();
		$verified = $this->verify($use, $credential, $session, $user, $appPassword);
		if ($verified === null && !$final) {
			return;
		}
		$use->resolved = true;
		if ($verified === true) {
			$switch = $use->switch ?? ($use->unknown ? $this->track($credential->keyMaterial(), $credential->userTag()) : null);
			if ($switch !== null) {
				$this->record($switch, $credential->scheme, $appPassword !== null, $session, $user);
			}
			return;
		}
		$this->trackSessionCookie($use, $session, $user);
	}

	/**
	 * @return ?bool null while it cannot be told yet
	 */
	private function verify(CredentialUse $use, PresentedCredential $credential, CoreSession $session, IUser $user, #[\SensitiveParameter] ?string $appPassword): ?bool {
		return match ($credential->scheme) {
			PresentedCredential::SCHEME_SESSION => $credential->matches($session->sessionId()),
			PresentedCredential::SCHEME_BEARER => $appPassword === null ? null : $credential->matches($appPassword),
			default => match (true) {
				$appPassword !== null => $credential->matches($appPassword),
				$use->passwordLoginUid === $user->getUID()
					&& (strcasecmp((string)$use->passwordLoginName, $credential->basicUser) === 0 || $user->getUID() === $credential->basicUser) => true,
				default => null,
			},
		};
	}

	/**
	 * The request sent an Authorization header that did not log it in, and
	 * its session cookie did: track the cookie.
	 */
	private function trackSessionCookie(CredentialUse $use, CoreSession $session, IUser $user): void {
		if (!$use->hasSessionCookie || $use->scheme === PresentedCredential::SCHEME_SESSION || $use->passwordLoginUid !== null) {
			return;
		}
		$cookie = PresentedCredential::sessionCookieOf($this->request, $this->sessionCookieName());
		if ($cookie === null || !$cookie->matches($session->sessionId())) {
			return;
		}
		$switch = $this->track($cookie->keyMaterial(), $cookie->userTag());
		if ($switch !== null) {
			$this->record($switch, PresentedCredential::SCHEME_SESSION, false, $session, $user);
		}
	}

	/**
	 * Track a credential that logged this request in, creating its entry
	 * if it has none.
	 */
	private function track(#[\SensitiveParameter] string $keyMaterial, string $userTag): ?CredentialSwitch {
		$source = SourceKey::tryFromIp($this->request->getRemoteAddress());
		if ($source === null) {
			return null;
		}
		return $this->container->get(CredentialTracker::class)->track(
			$this->container->get(Fingerprinter::class)->credential($keyMaterial),
			$source,
			$userTag,
			$this->container->get(ITimeFactory::class)->getTime(),
			fn (): bool => $this->container->get(RemoteAddressResolver::class)->isIgnored($source),
		);
	}

	/**
	 * @param PresentedCredential::SCHEME_* $scheme
	 */
	private function record(CredentialSwitch $switch, string $scheme, bool $appPassword, CoreSession $session, IUser $user): void {
		if ($scheme === PresentedCredential::SCHEME_SESSION) {
			$kind = TokenConcurrentUse::KIND_SESSION;
			$sessionTokenId = $session->tokenId();
			$tokenId = $sessionTokenId;
		} elseif ($appPassword) {
			$kind = TokenConcurrentUse::KIND_APP_PASSWORD;
			$tokenId = $session->loginTokenId();
			$sessionTokenId = null;
		} else {
			$kind = TokenConcurrentUse::KIND_PASSWORD;
			$tokenId = null;
			$sessionTokenId = $session->tokenId();
		}
		$userAgent = $this->request->getHeader('User-Agent');
		$this->container->get(SignalDispatcher::class)->dispatch(new CredentialSwitched(
			$switch,
			$kind,
			$scheme,
			$user,
			$tokenId,
			$sessionTokenId,
			$userAgent === '' ? null : $userAgent,
		));
	}

	private function sessionCookieName(): string {
		return $this->config->getSystemValueString('instanceid', '');
	}
}
