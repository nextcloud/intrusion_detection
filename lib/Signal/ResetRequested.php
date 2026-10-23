<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Signal;

use OCA\IntrusionDetection\Detection\AttemptRecord;

/**
 * A password reset request, as recorded.
 */
final class ResetRequested implements ISignal {
	public function __construct(
		#[\SensitiveParameter]
		public readonly AttemptRecord $attempt,
		public readonly ?string $userAgent,
	) {
	}

	/**
	 * @return array<string, mixed>
	 */
	public function __debugInfo(): array {
		return ['source' => $this->attempt->source->ip];
	}
}
