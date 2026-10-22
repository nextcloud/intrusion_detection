<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check;

use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Detection\DetectionDraft;

/**
 * A check whose rules answer with different responses. Share link attacks,
 * for example, block an address that guesses tokens, but tell the owner when
 * a share's password is guessed from many addresses.
 *
 * Detectors and simulations both ask the check, so they always agree.
 */
interface ISelectsResponses {
	/**
	 * The responses to run for one detection, out of the configured ones.
	 *
	 * @param list<ResponseType> $configured the responses the admin selected for the check
	 * @param array<string, int|float|bool|string|list<string>> $params the check's current parameters
	 * @return list<ResponseType>
	 */
	public function responsesFor(DetectionDraft $draft, array $configured, array $params): array;
}
