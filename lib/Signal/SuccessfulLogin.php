<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Signal;

use OCA\IntrusionDetection\Login\LoginContext;

/**
 * A successful password login, through the login form or from an app that
 * sends the password, before it is decided whether it needs confirmation.
 */
final class SuccessfulLogin implements ISignal {
	public function __construct(
		#[\SensitiveParameter]
		public readonly LoginContext $login,
	) {
	}

	/**
	 * @return array<string, mixed>
	 */
	public function __debugInfo(): array {
		return ['login' => $this->login];
	}
}
