<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\AdminChange;

/**
 * Request-local state of the four-eyes approval:
 *
 * - a permit that lets exactly one add of one account to one group through
 *   without asking again, set by {@see ApprovalService} after a second
 *   administrator approved, and used up by that add;
 * - which removal is the app's own revert, so it is not reported as an
 *   administrator removed.
 *
 * It lives only in this object, which exists once per request. Nothing a
 * client sends can set it, and it never reaches the database or a cache.
 */
class GrantPermit {
	/** @var array<string, array<string, scalar>> */
	private array $permits = [];
	/** @var array<string, true> */
	private array $reverting = [];

	/**
	 * @param array<string, scalar> $facts what to tell about the approval when the add is reported
	 */
	public function allow(string $uid, string $gid, array $facts = []): void {
		$this->permits[self::key($uid, $gid)] = $facts;
	}

	/**
	 * Use the permit for this exact account and group.
	 *
	 * @return ?array<string, scalar> the permit's facts, or null when there is none; a second call returns null
	 */
	public function consume(string $uid, string $gid): ?array {
		$key = self::key($uid, $gid);
		if (!isset($this->permits[$key])) {
			return null;
		}
		$facts = $this->permits[$key];
		unset($this->permits[$key]);
		return $facts;
	}

	public function revoke(string $uid, string $gid): void {
		unset($this->permits[self::key($uid, $gid)]);
	}

	public function beginRevert(string $uid, string $gid): void {
		$this->reverting[self::key($uid, $gid)] = true;
	}

	public function endRevert(string $uid, string $gid): void {
		unset($this->reverting[self::key($uid, $gid)]);
	}

	public function isReverting(string $uid, string $gid): bool {
		return isset($this->reverting[self::key($uid, $gid)]);
	}

	private static function key(string $uid, string $gid): string {
		return $uid . "\0" . $gid;
	}
}
