<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Takeover;

/**
 * The accounts whose password is being reset through the "forgot password"
 * email in this request, between core's events before and after the reset.
 * A new password set that way proves access to the email address, so it is
 * logged as a reset and never counts as a takeover sign.
 */
class ResetTracker {
	/** @var array<string, true> */
	private array $resetting = [];

	public function start(string $uid): void {
		$this->resetting[$uid] = true;
	}

	public function end(string $uid): void {
		unset($this->resetting[$uid]);
	}

	public function isResetting(string $uid): bool {
		return isset($this->resetting[$uid]);
	}
}
