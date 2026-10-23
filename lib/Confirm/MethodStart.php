<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

/**
 * How starting a confirmation method went ({@see IConfirmationMethod::begin()}),
 * and the step-up with what the method keeps in it.
 */
final class MethodStart {
	/**
	 * @param IConfirmationMethod::CONFIRMED|IConfirmationMethod::PENDING|IConfirmationMethod::UNAVAILABLE $outcome
	 */
	public function __construct(
		public readonly string $outcome,
		public readonly StepUpState $state,
	) {
	}
}
