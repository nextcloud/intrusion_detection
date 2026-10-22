<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Explain;

use OCA\IntrusionDetection\Db\Detection;

/**
 * A check whose detections, or some of them, are kept from the affected
 * user: they record something about the account that is no security event
 * for its owner, or that only the administrators can judge. Kept
 * detections are not listed or counted on the user's security page, not
 * shown in the login notice, and never sent to the user.
 *
 * Detections of a check without {@see IExplainsToUser} are always kept
 * from the user.
 */
interface IKeepsFromUser {
	public function keepsFromUser(Detection $detection): bool;
}
