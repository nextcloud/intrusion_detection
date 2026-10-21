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
 * A check that can tell the affected user, in their words, what happened.
 * The user notification response uses it; the texts never contain
 * thresholds, other users or admin notes.
 */
interface IExplainsToUser {
	/**
	 * @param IL10N $l in the user's language
	 */
	public function userNotice(Detection $detection, IL10N $l): UserNotice;
}
