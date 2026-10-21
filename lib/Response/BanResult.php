<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Response;

use OCA\IntrusionDetection\Db\Ban;

final class BanResult {
	public const BANNED = 'banned';
	public const EXTENDED = 'extended';
	public const ALREADY = 'already';
	public const SKIPPED_BYPASS = 'bypass';
	public const SKIPPED_NEVER = 'never';
	public const SKIPPED_SHARED = 'shared';
	/** A private address that is probably the reverse proxy, while no trusted proxy is configured */
	public const SKIPPED_PROXY = 'proxy';
	/** Someone confirmed a login from it recently, or an administrator logged in from it */
	public const SKIPPED_TRUSTED = 'trusted';

	/**
	 * @param self::* $outcome
	 * @param ?Ban $netBan the network ban added by subnet escalation, if any
	 * @param int $sharedUsers for SKIPPED_SHARED and SKIPPED_PROXY: how many people logged in from the address
	 */
	public function __construct(
		public readonly string $outcome,
		public readonly ?Ban $ban = null,
		public readonly ?Ban $netBan = null,
		public readonly int $sharedUsers = 0,
	) {
	}

	public function isBlocked(): bool {
		return $this->ban !== null;
	}
}
