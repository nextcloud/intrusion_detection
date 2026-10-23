<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Signal;

use OCA\IntrusionDetection\Net\SourceKey;
use OCP\IUser;

/**
 * A failed second-factor challenge after a correct password, backup codes
 * included.
 */
final class SecondFactorFailure implements ISignal {
	public function __construct(
		public readonly IUser $user,
		public readonly string $providerId,
		public readonly string $providerName,
		public readonly SourceKey $source,
		public readonly ?string $userAgent,
	) {
	}
}
