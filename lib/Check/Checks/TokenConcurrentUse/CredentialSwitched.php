<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\TokenConcurrentUse;

use OCA\IntrusionDetection\Signal\ISignal;
use OCP\IUser;

/**
 * A credential was used from two networks at the same time, and a login
 * showed whose it is ({@see CredentialUseResolver}).
 */
final class CredentialSwitched implements ISignal {
	/**
	 * @param TokenConcurrentUse::KIND_* $kind
	 * @param PresentedCredential::SCHEME_* $scheme
	 * @param ?int $tokenId the app password or session token that was used
	 * @param ?int $sessionTokenId the browser session's token, if one is involved
	 */
	public function __construct(
		public readonly CredentialSwitch $switch,
		public readonly string $kind,
		public readonly string $scheme,
		public readonly IUser $user,
		public readonly ?int $tokenId,
		public readonly ?int $sessionTokenId,
		public readonly ?string $userAgent,
	) {
	}
}
