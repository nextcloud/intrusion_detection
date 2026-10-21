<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Config;

use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Check\Requirement;

/**
 * The mode a check is set to, the mode it runs in, and why they differ.
 */
final class ModeState {
	public const REASON_DISABLED = 'disabled';
	public const REASON_LEARNING = 'learning';
	public const REASON_REQUIREMENT = 'requirement';
	/** The check acts on anonymous requests, but only observes those of logged-in users */
	public const REASON_AUTHENTICATED = 'authenticated';

	/**
	 * @param self::REASON_*|null $reason
	 */
	public function __construct(
		public readonly Mode $configured,
		public readonly Mode $effective,
		public readonly ?string $reason = null,
		public readonly ?Requirement $missing = null,
	) {
	}

	public function acts(): bool {
		return $this->effective->acts();
	}

	public function runs(): bool {
		return $this->effective->runs();
	}
}
