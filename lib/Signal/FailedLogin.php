<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Signal;

use OCA\IntrusionDetection\Net\SourceKey;

/**
 * A failed password check (login form, Basic auth on WebDAV and OCS, login
 * flow), before anything is recorded. The login name may be a mistyped
 * password and the password is the attempt itself: both are only compared,
 * never stored or logged.
 */
final class FailedLogin implements ISignal {
	public function __construct(
		public readonly SourceKey $source,
		#[\SensitiveParameter]
		public readonly string $loginName,
		#[\SensitiveParameter]
		public readonly ?string $password,
		public readonly ?string $userAgent,
	) {
	}

	/**
	 * @return array<string, mixed>
	 */
	public function __debugInfo(): array {
		return ['source' => $this->source->ip];
	}
}
