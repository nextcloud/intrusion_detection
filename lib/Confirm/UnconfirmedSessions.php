<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

use OCA\IntrusionDetection\Confirm\Db\StepUpSessionMapper;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\State\HotState;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IConfig;
use Psr\Log\LoggerInterface;

/**
 * The sessions whose login still waits for its confirmation, or was refused,
 * remembered on the server by a keyed fingerprint of the session id.
 *
 * The step-up state lives in the PHP session, but a session can come back
 * without it: through the remember-me cookie, which core issues at the end
 * of the login, or from its session token when the PHP session data is
 * gone. Such a resumed session must not skip the confirmation. A login is
 * remembered here as long as its session could be resumed, and forgotten
 * when it is confirmed or ended.
 *
 * Normal logins cost nothing: the table is only read while an unconfirmed
 * session may exist, which a global setting tells without a query.
 */
class UnconfirmedSessions {
	/** Core's defaults for how long a remembered login and a session last */
	public const DEFAULT_REMEMBER_LIFETIME = 15 * 86400;
	public const DEFAULT_SESSION_LIFETIME = 86400;

	public function __construct(
		private readonly StepUpSessionMapper $mapper,
		private readonly Fingerprinter $fingerprinter,
		private readonly IConfig $config,
		private readonly ITimeFactory $timeFactory,
		private readonly LoggerInterface $logger,
		private readonly HotState $hotState,
	) {
	}

	/**
	 * @param ?StepUpState $pending a login that waits for its confirmation, which a background job ends at its deadline
	 */
	public function remember(#[\SensitiveParameter] string $sessionId, string $uid, ?StepUpState $pending = null): void {
		$now = $this->timeFactory->getTime();
		$expires = $now + $this->lifetime();
		$this->mapper->record(
			$this->fingerprinter->session($sessionId),
			$uid,
			$now,
			$expires,
			$pending?->deadline,
			$pending?->ip,
			$pending === null ? [] : $pending->policies,
		);
		if ($this->hotState->stepUpSessionsUntil() < $expires) {
			$this->hotState->setStepUpSessionsUntil($expires);
		}
	}

	public function extendDeadline(#[\SensitiveParameter] string $sessionId, int $deadline): void {
		try {
			$this->mapper->extendDeadline($this->fingerprinter->session($sessionId), $deadline);
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not extend the wait of an unconfirmed session', ['exception' => $e]);
		}
	}

	/**
	 * Count one try of the session's email code on the server; see
	 * {@see StepUpSessionMapper::takeAttempt()}. A pending login whose
	 * session is not remembered (any more) has no try left: it was ended
	 * meanwhile. Only a session without an id, which is never remembered,
	 * gets 0, and its tries are counted in the session alone.
	 */
	public function takeCodeAttempt(#[\SensitiveParameter] string $sessionId, int $max): ?int {
		if ($sessionId === '') {
			return 0;
		}
		return $this->mapper->takeAttempt($this->fingerprinter->session($sessionId), $max);
	}

	public function forget(#[\SensitiveParameter] string $sessionId): void {
		try {
			$this->mapper->delete($this->fingerprinter->session($sessionId));
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not forget an unconfirmed session', ['exception' => $e]);
		}
	}

	/**
	 * The account whose unconfirmed login this session is, or null.
	 */
	public function accountOf(#[\SensitiveParameter] string $sessionId): ?string {
		if ($sessionId === '' || !$this->mayExist()) {
			return null;
		}
		return $this->mapper->find($this->fingerprinter->session($sessionId), $this->timeFactory->getTime());
	}

	/**
	 * Whether any unconfirmed session may still exist, without a query.
	 */
	public function mayExist(): bool {
		return self::mayExistIn($this->hotState, $this->timeFactory->getTime());
	}

	/**
	 * The same, for callers that have not built this service.
	 */
	public static function mayExistIn(HotState $hotState, int $now): bool {
		return $hotState->stepUpSessionsUntil() > $now;
	}

	/**
	 * As long as core could resume the session: the longer of the
	 * remember-me cookie's and the session's lifetime, and an hour more.
	 */
	private function lifetime(): int {
		return max(
			$this->config->getSystemValueInt('remember_login_cookie_lifetime', self::DEFAULT_REMEMBER_LIFETIME),
			$this->config->getSystemValueInt('session_lifetime', self::DEFAULT_SESSION_LIFETIME),
		) + 3600;
	}
}
