<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\TrustedNetwork;

use OCA\IntrusionDetection\Net\SourceKey;

/**
 * No network is trusted: used while users cannot confirm networks as their own.
 */
final class NullTrustedNetworks implements ITrustedNetworks {
	#[\Override]
	public function isTrusted(string $uid, SourceKey $source): bool {
		return false;
	}
}
