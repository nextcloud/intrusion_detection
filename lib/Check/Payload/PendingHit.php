<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Payload;

use OCA\IntrusionDetection\Net\SourceKey;

/**
 * A hit in a request that carries credentials, kept until the request knows
 * whether it is logged in. At guard time a session cookie only says that a
 * session exists: the login page gives one to every visitor, and an attacker
 * can send any cookie. So the hit is decided after authentication.
 */
final class PendingHit {
	public const CREDENTIAL_BASIC = 'basic';
	public const CREDENTIAL_BEARER = 'bearer';
	public const CREDENTIAL_OTHER = 'authorization';
	public const CREDENTIAL_SESSION = 'session';
	public const CREDENTIAL_REMEMBER_ME = 'remember_me';

	/**
	 * @param self::CREDENTIAL_* $credential
	 * @param bool $lure the request is a possible lure ({@see \OCA\IntrusionDetection\Net\FetchMetadata})
	 */
	public function __construct(
		public readonly PayloadHit $hit,
		public readonly SourceKey $source,
		public readonly string $credential,
		public readonly ?string $userAgent,
		public readonly bool $lure = false,
	) {
	}
}
