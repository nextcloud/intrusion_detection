<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Signal;

use OCP\IUser;

/**
 * A successful login with the account's password through the login form
 * ({@see \OCA\IntrusionDetection\Login\InteractiveLogin}). The password is
 * only checked, never stored or logged.
 */
final class InteractivePasswordLogin implements ISignal {
	public function __construct(
		public readonly IUser $user,
		#[\SensitiveParameter]
		public readonly string $password,
		public readonly ?string $userAgent,
	) {
	}

	/**
	 * @return array<string, mixed>
	 */
	public function __debugInfo(): array {
		return ['uid' => $this->user->getUID()];
	}
}
