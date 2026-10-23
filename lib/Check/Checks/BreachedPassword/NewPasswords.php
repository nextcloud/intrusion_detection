<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\BreachedPassword;

use OCA\IntrusionDetection\Breach\PwnedPasswordsClient;
use OCA\IntrusionDetection\Config\CheckSettings;

/**
 * Whether a password someone is about to choose is on the breach list,
 * while the breach check runs, with its threshold. A breached password
 * must not be swapped for another one. Fails open like the check: when
 * the list cannot be asked, the password policy alone decides.
 */
class NewPasswords {
	public function __construct(
		private readonly CheckSettings $settings,
		private readonly PwnedPasswordsClient $client,
	) {
	}

	public function isBreached(#[\SensitiveParameter] string $password): bool {
		if (!$this->settings->modeState(BreachedPassword::ID)->runs()) {
			return false;
		}
		$count = $this->client->count($password);
		return $count !== null && $count >= $this->settings->paramInt(BreachedPassword::ID, 'min_count');
	}
}
