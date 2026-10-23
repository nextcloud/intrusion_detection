<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Signal;

use OCA\IntrusionDetection\Detection\AttemptRecord;

/**
 * A failed login as recorded, for the checks that count failed logins. The
 * password is only passed on to be fingerprinted, never stored or logged.
 */
final class FailedLoginAttempt implements ISignal {
	public function __construct(
		#[\SensitiveParameter]
		public readonly AttemptRecord $attempt,
		#[\SensitiveParameter]
		public readonly ?string $password,
		public readonly ?string $userAgent,
	) {
	}

	/**
	 * @return array<string, mixed>
	 */
	public function __debugInfo(): array {
		return ['kind' => $this->attempt->kind->name, 'source' => $this->attempt->source->ip];
	}
}
