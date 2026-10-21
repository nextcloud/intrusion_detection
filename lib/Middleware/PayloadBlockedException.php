<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Middleware;

use OCP\Security\Guard\GuardDecision;

/**
 * Stops a controller from running because the request's address was just blocked.
 */
final class PayloadBlockedException extends \Exception {
	public function __construct(
		public readonly GuardDecision $decision,
	) {
		parent::__construct('Blocked by the injection probe check');
	}
}
