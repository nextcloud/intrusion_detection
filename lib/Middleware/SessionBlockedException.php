<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Middleware;

use OCA\IntrusionDetection\SessionState\SessionBlock;

/**
 * Thrown before a controller runs when a session-state rule blocks the
 * request; {@see SessionStateMiddleware::afterException()} answers it.
 */
class SessionBlockedException extends \Exception {
	public function __construct(
		public readonly SessionBlock $block,
	) {
		parent::__construct($block->error);
	}
}
