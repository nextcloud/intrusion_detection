<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Signal;

use OCA\IntrusionDetection\Net\SourceKey;
use OCP\Authentication\Token\IToken;

/**
 * A login flow v2 request was granted: where it was started, when, and
 * where it was approved (the current request).
 */
final class LoginFlowGranted implements ISignal {
	public function __construct(
		public readonly IToken $token,
		public readonly ?string $initiatorIp,
		public readonly int $startedAt,
		public readonly SourceKey $granter,
		public readonly ?string $userAgent,
	) {
	}
}
