<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Decoy;

use OCP\Security\ISecureRandom;

/**
 * The two shapes of real Nextcloud credentials a decoy can imitate, so that
 * it looks real wherever it is planted.
 */
enum DecoyFormat: string {
	/** Like an app password from the personal security settings: 5 groups of 5, e.g. "AbCdE-fGhJk-…" */
	case AppPassword = 'app-password';
	/** Like a token from a login flow or occ user:auth-tokens:add: 72 letters and digits */
	case Token = 'token';

	/**
	 * A new random secret, generated the way core generates the real thing
	 * (AuthSettingsController::generateRandomDeviceToken() and the login flows).
	 */
	public function generate(ISecureRandom $random): string {
		return match ($this) {
			self::AppPassword => implode('-', array_map(
				static fn (int $group): string => $random->generate(5, ISecureRandom::CHAR_HUMAN_READABLE),
				range(1, 5),
			)),
			self::Token => $random->generate(72, ISecureRandom::CHAR_UPPER . ISecureRandom::CHAR_LOWER . ISecureRandom::CHAR_DIGITS),
		};
	}
}
