<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check;

use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Net\SourceKey;

/**
 * A check that can show what it would report for synthetic input at its
 * current thresholds, without recording, blocking or notifying anything.
 */
interface ISimulatable {
	/**
	 * The detection this check would make for an attack that just reaches
	 * the given thresholds, coming from `$source`.
	 *
	 * @param array<string, int|float|bool|string|list<string>> $params the check's current parameters
	 */
	public function simulate(SourceKey $source, int $now, array $params): DetectionDraft;
}
