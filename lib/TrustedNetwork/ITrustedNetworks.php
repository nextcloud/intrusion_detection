<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\TrustedNetwork;

use OCA\IntrusionDetection\Net\SourceKey;

/**
 * The networks a user confirmed as their own by answering "Yes, it was me"
 * (concept section 11.8). Detections from such a network are less
 * suspicious, e.g. a login flow started there is not reported as phishing.
 */
interface ITrustedNetworks {
	/**
	 * Whether the network of the address (its /24 or /64) is one of the
	 * user's trusted networks right now.
	 */
	public function isTrusted(string $uid, SourceKey $source): bool;
}
