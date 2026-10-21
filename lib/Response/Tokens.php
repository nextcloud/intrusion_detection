<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Response;

use OC\Authentication\Token\IProvider as PrivateTokenProvider;
use OCP\Authentication\Token\IProvider;
use OCP\Authentication\Token\IToken;

/**
 * Looks up and invalidates single sessions and app passwords by their
 * database id, without touching the account's other devices.
 */
class Tokens {
	/** Token names are user agents or chosen names; long ones are cut */
	public const MAX_NAME = 100;

	public function __construct(
		private readonly IProvider $tokenProvider,
		private readonly PrivateTokenProvider $tokenLookup,
	) {
	}

	/**
	 * The token with this id, if it exists and belongs to the account.
	 */
	public function find(string $uid, int $tokenId): ?IToken {
		try {
			// The public provider can only look tokens up by their secret.
			$token = $this->tokenLookup->getTokenById($tokenId);
		} catch (\Throwable) {
			return null;
		}
		return $token->getUID() === $uid ? $token : null;
	}

	/**
	 * Invalidate one token of the account.
	 *
	 * @return ?array{id: int, name: string} what was invalidated, or null if the token no longer exists
	 */
	public function invalidate(string $uid, int $tokenId): ?array {
		$token = $this->find($uid, $tokenId);
		if ($token === null) {
			return null;
		}
		$this->tokenProvider->invalidateTokenById($uid, $tokenId);
		return ['id' => $tokenId, 'name' => self::name($token)];
	}

	public static function name(IToken $token): string {
		$name = trim((string)preg_replace('/[\x00-\x1f\x7f]+/u', ' ', $token->getName()));
		return mb_strlen($name) > self::MAX_NAME ? mb_substr($name, 0, self::MAX_NAME - 1) . '…' : $name;
	}
}
