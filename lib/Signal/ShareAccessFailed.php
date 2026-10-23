<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Signal;

use OCA\IntrusionDetection\Detection\AttemptRecord;
use OCP\Share\IShare;

/**
 * A failed access to a public share link, as recorded: an unknown token
 * (no share), or a wrong password for a share.
 */
final class ShareAccessFailed implements ISignal {
	public function __construct(
		#[\SensitiveParameter]
		public readonly AttemptRecord $attempt,
		public readonly ?IShare $share,
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
