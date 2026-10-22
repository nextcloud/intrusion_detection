<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\StaleCredential;

use OC\Authentication\Token\IProvider as PrivateTokenProvider;
use OC\Authentication\Token\PublicKeyToken;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Guide\SecureAccountOverview;
use OCA\IntrusionDetection\Response\Tokens;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCA\IntrusionDetection\SessionState\CurrentSession;
use OCA\IntrusionDetection\StaleCredential\Db\StaleTokenMapper;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Authentication\Token\IProvider;
use OCP\Authentication\Token\IToken;
use OCP\IL10N;

/**
 * One account's app passwords and remembered browser sessions that have
 * not been used for DAYS days: a thief who finds one can use it unnoticed.
 * Listed by id, name, kind and last use, never by secret, and removed
 * through core's token provider. The session of the current request is
 * never counted.
 *
 * @psalm-import-type IntrusionDetectionStaleCredential from ResponseDefinitions
 */
class StaleCredentials {
	/** Unused for this many days, a credential counts as stale */
	public const DAYS = 90;
	public const KIND_APP_PASSWORD = 'app_password';
	public const KIND_SESSION = 'session';

	public function __construct(
		private readonly PrivateTokenProvider $tokenLookup,
		private readonly IProvider $tokenProvider,
		private readonly CurrentSession $currentSession,
		private readonly ITimeFactory $timeFactory,
		private readonly AuditLogger $audit,
	) {
	}

	/**
	 * Last used before this time, a credential is stale.
	 */
	public function cutoff(int $days = self::DAYS): int {
		return $this->timeFactory->getTime() - $days * 86400;
	}

	/**
	 * The account's stale credentials, longest unused first.
	 *
	 * @return list<IntrusionDetectionStaleCredential>
	 */
	public function forUser(string $uid, IL10N $l): array {
		$list = array_map(static fn (PublicKeyToken $token): array => [
			'id' => $token->getId(),
			'name' => $token->getType() === IToken::TEMPORARY_TOKEN ? SecureAccountOverview::browserName($token, $l) : Tokens::name($token),
			'kind' => $token->getType() === IToken::PERMANENT_TOKEN ? self::KIND_APP_PASSWORD : self::KIND_SESSION,
			'lastUsed' => $token->getLastActivity(),
		], $this->unusedSince($uid, $this->cutoff()));
		usort($list, static fn (array $a, array $b): int => [$a['lastUsed'], $a['id']] <=> [$b['lastUsed'], $b['id']]);
		return $list;
	}

	/**
	 * Remove one stale credential of the account.
	 *
	 * @return ?array{id: int, name: string} what was removed, or null when the account has no such stale credential
	 */
	public function remove(string $uid, int $tokenId): ?array {
		foreach ($this->unusedSince($uid, $this->cutoff()) as $token) {
			if ($token->getId() === $tokenId) {
				$this->tokenProvider->invalidateTokenById($uid, $tokenId);
				$this->audit->log('%s removed an app password or device unused for %s days: %s', ['uid' => $uid, 'days' => (string)self::DAYS, 'name' => Tokens::name($token)]);
				return ['id' => $tokenId, 'name' => Tokens::name($token)];
			}
		}
		return null;
	}

	/**
	 * Remove the account's credentials last used before $before.
	 *
	 * @param string $by who removed them, for the audit log: the user, an administrator or the daily job
	 * @return list<array{name: string, kind: string}> what was removed
	 */
	public function removeUnusedSince(string $uid, int $before, string $by): array {
		$removed = [];
		foreach ($this->unusedSince($uid, $before) as $token) {
			$this->tokenProvider->invalidateTokenById($uid, $token->getId());
			$removed[] = ['name' => Tokens::name($token), 'kind' => $token->getType() === IToken::PERMANENT_TOKEN ? self::KIND_APP_PASSWORD : self::KIND_SESSION];
		}
		if ($removed !== []) {
			$this->audit->log('%s removed %s app passwords and devices of %s unused for %s days', [
				'by' => $by,
				'count' => (string)count($removed),
				'uid' => $uid,
				'days' => (string)intdiv($this->timeFactory->getTime() - $before, 86400),
			]);
		}
		return $removed;
	}

	/**
	 * @return list<PublicKeyToken>
	 */
	private function unusedSince(string $uid, int $before): array {
		$current = $this->currentSession->tokenId();
		return array_values(array_filter(
			$this->tokenLookup->getTokenByUser($uid),
			static fn (IToken $token): bool => $token instanceof PublicKeyToken
				&& $token->getUID() === $uid
				&& $token->getId() !== $current
				&& StaleTokenMapper::isLongLived($token->getType(), $token->getRemember())
				&& $token->getLastActivity() < $before,
		));
	}
}
