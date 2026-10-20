<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Explain;

use OCA\IntrusionDetection\Db\Detection;
use OCP\IL10N;

/**
 * A check that tells in its own words what happened in one of its detections.
 * Without it, a generic sentence built from the stored facts is used.
 *
 * The narrative must use the thresholds stored in the detection, not the
 * current settings: it explains what happened then.
 */
interface IExplainsDetection {
	/**
	 * @return list<string> sentences, plain text (the page and emails escape them)
	 */
	public function narrative(Detection $detection, IL10N $l): array;
}
