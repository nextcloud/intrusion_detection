<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Address;

use OCA\IntrusionDetection\Net\SourceKey;

/**
 * Adds facts about an address to its verdict: a block from an external list,
 * or network attributes. Runs only when a verdict is resolved, never per request.
 *
 * Verdicts of IPv6 addresses are cached for their whole /64. Facts that do
 * not hold for every address of the /64 must say so (`perAddress`).
 */
interface IAddressFactsProvider {
	public function facts(SourceKey $source): AddressFacts;
}
