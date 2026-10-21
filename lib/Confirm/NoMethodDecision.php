<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

/**
 * The combined outcome of the policies of one login that nothing can
 * confirm; see {@see ConfirmationPolicy::noMethodDecision()}.
 */
final class NoMethodDecision {
	public function __construct(
		public readonly bool $refuse,
		/** Allowed: tell the user and the administrators */
		public readonly bool $notify,
		/** Allowed: require a new password */
		public readonly bool $forceChange,
	) {
	}
}
