<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Signal;

/**
 * The account holder changed a security setting of their account (email,
 * password, second factor …), recorded in the security change log.
 */
final class SecurityChanged implements ISignal {
	/**
	 * @param ?int $sessionTokenId the session the change was made with
	 */
	public function __construct(
		public readonly string $uid,
		public readonly ?int $sessionTokenId,
	) {
	}
}
