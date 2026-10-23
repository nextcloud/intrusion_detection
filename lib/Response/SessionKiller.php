<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Response;

use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Db\TokenOriginMapper;
use OCA\IntrusionDetection\Login\CoreSession;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IUserSession;

/**
 * Ends one suspicious session and the app passwords that came with it
 * (concept section 11.4):
 *
 * 1. the session's token; when it is the current request's session, the
 *    request is logged out as well;
 * 2. the app passwords created from that session, and those created for the
 *    same account from the same address within the last hour.
 *
 * Every other session and app password of the account keeps working. The
 * result lists the ids and names of what was ended, never a token.
 */
class SessionKiller {
	/** App passwords from the same address count when created this recently */
	public const SAME_ADDRESS_WINDOW = 3600;
	/** At most this many app passwords are ended per call */
	public const MAX_TOKENS = 100;

	public function __construct(
		private readonly Tokens $tokens,
		private readonly TokenOriginMapper $origins,
		private readonly CoreSession $coreSession,
		private readonly IUserSession $userSession,
		private readonly ITimeFactory $timeFactory,
		private readonly AuditLogger $audit,
	) {
	}

	/**
	 * @return array{session: ?array{id: int, name: string}, tokens: list<array{id: int, name: string}>, loggedOut: bool}
	 */
	public function kill(string $uid, ?int $sessionTokenId, ?string $ip, ?int $detectionId = null): array {
		$session = null;
		$loggedOut = false;
		if ($sessionTokenId !== null) {
			$isCurrent = $this->coreSession->tokenId() === $sessionTokenId
				&& $this->userSession->getUser()?->getUID() === $uid;
			$session = $this->tokens->invalidate($uid, $sessionTokenId);
			if ($isCurrent) {
				$this->userSession->logout();
				$loggedOut = true;
			}
		}

		$ids = $sessionTokenId === null ? [] : $this->origins->createdBy($uid, $sessionTokenId, self::MAX_TOKENS);
		if ($ip !== null) {
			$since = $this->timeFactory->getTime() - self::SAME_ADDRESS_WINDOW;
			$ids = array_merge($ids, $this->origins->createdFrom($uid, $ip, $since, self::MAX_TOKENS));
		}
		$revoked = [];
		foreach (array_slice(array_values(array_unique($ids)), 0, self::MAX_TOKENS) as $tokenId) {
			if ($tokenId === $sessionTokenId) {
				continue;
			}
			$token = $this->tokens->invalidate($uid, $tokenId);
			if ($token !== null) {
				$revoked[] = $token;
			}
		}

		if ($session !== null || $revoked !== []) {
			$this->audit->log('session %s and %s app passwords of %s ended (detection %s)', [
				'session' => $session['id'] ?? null,
				'tokens' => (string)count($revoked),
				'uid' => $uid,
				'detection' => $detectionId,
			]);
		}
		return ['session' => $session, 'tokens' => $revoked, 'loggedOut' => $loggedOut];
	}
}
