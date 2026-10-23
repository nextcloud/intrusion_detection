<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Response;

use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Db\TokenOriginMapper;

/**
 * Revokes one app password or token, and the app passwords that were
 * created while logged in with it (concept section 11.4). The account's
 * other devices keep working.
 */
class TokenRevoker {
	/** At most this many app passwords created from the token are revoked with it */
	public const MAX_CHILDREN = 100;

	public function __construct(
		private readonly Tokens $tokens,
		private readonly TokenOriginMapper $origins,
		private readonly AuditLogger $audit,
	) {
	}

	/**
	 * @return array{token: ?array{id: int, name: string}, tokens: list<array{id: int, name: string}>}
	 */
	public function revoke(string $uid, int $tokenId, ?string $detectionId = null): array {
		$token = $this->tokens->invalidate($uid, $tokenId);
		$children = [];
		foreach ($this->origins->createdBy($uid, $tokenId, self::MAX_CHILDREN) as $childId) {
			if ($childId === $tokenId) {
				continue;
			}
			$child = $this->tokens->invalidate($uid, $childId);
			if ($child !== null) {
				$children[] = $child;
			}
		}
		if ($token !== null || $children !== []) {
			$this->audit->log('token %s and %s app passwords created from it revoked for %s (detection %s)', [
				'token' => $tokenId,
				'children' => (string)count($children),
				'uid' => $uid,
				'detection' => $detectionId,
			]);
		}
		return ['token' => $token, 'tokens' => $children];
	}
}
