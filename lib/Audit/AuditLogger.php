<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Audit;

use OCP\EventDispatcher\IEventDispatcher;
use OCP\Log\Audit\CriticalActionPerformedEvent;

/**
 * Writes to the admin_audit log through core's critical-action event.
 *
 * Messages use `%s` placeholders; parameters are strings. Never pass a
 * password, fingerprint, token or decoy secret.
 */
class AuditLogger {
	public function __construct(
		private readonly IEventDispatcher $dispatcher,
	) {
	}

	/**
	 * @param array<string, scalar|null> $parameters
	 */
	public function log(string $message, array $parameters = []): void {
		$this->dispatcher->dispatchTyped(new CriticalActionPerformedEvent(
			'Intrusion detection: ' . $message,
			array_map(static fn (mixed $v): string => $v === null ? '' : (string)$v, $parameters),
		));
	}
}
