<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Signal;

use OCA\IntrusionDetection\Definition\Severity;

/**
 * A change that gives or takes administration rights or weakens security:
 * an administrator granted, an app switched off, a watched setting changed.
 */
final class AdminChanged implements ISignal {
	/**
	 * @param string $kind what changed, one of the admin change check's kinds
	 * @param ?string $subject the account the change was about
	 * @param array<string, mixed> $facts what the change was about (group, app, setting …)
	 * @param string $alertKey changes with the same key share one notification per hour
	 * @param bool $withAddress the address of the current request is the actor's
	 */
	public function __construct(
		public readonly string $kind,
		public readonly Severity $severity,
		public readonly string $actor,
		public readonly ?string $subject,
		public readonly array $facts,
		public readonly string $alertKey,
		public readonly bool $withAddress = true,
	) {
	}
}
