<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\NewLogin;

use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Signal\ISignal;
use OCP\IUser;

/**
 * A person logged in, and nothing asked or told them about the login: it
 * came from no remembered device and needed no confirmation
 * ({@see \OCA\IntrusionDetection\Listener\Login\NewLoginStep}).
 */
final class UnfamiliarLogin implements ISignal {
	/**
	 * @param bool $typedPassword the login typed the account's password
	 */
	public function __construct(
		public readonly IUser $user,
		public readonly SourceKey $source,
		public readonly ?string $userAgent,
		public readonly bool $typedPassword,
	) {
	}
}
