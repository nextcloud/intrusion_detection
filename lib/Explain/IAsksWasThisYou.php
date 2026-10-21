<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Explain;

use OCA\IntrusionDetection\Db\Detection;

/**
 * A check whose notice to the user asks "Was this you?" for some of its
 * detections. The user notification then offers the two answers, which
 * carry only the detection id; the server checks that it is the user's own.
 */
interface IAsksWasThisYou {
	public function asksWasThisYou(Detection $detection): bool;
}
