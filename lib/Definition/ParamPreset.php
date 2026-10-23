<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Definition;

/**
 * How a protection level changes a parameter, from its default. Parameters
 * without a preset (time windows, switches, lists, points) keep their value
 * at every level.
 */
enum ParamPreset: string {
	/** A count that makes a check fire: lower is stricter */
	case Limit = 'limit';
	/** How long a block lasts: longer is stricter */
	case BlockDuration = 'block_duration';

	/**
	 * The factor the default is multiplied by at a level.
	 */
	public function factor(ProtectionLevel $level): float {
		return match ($level) {
			ProtectionLevel::Strict => $this === self::Limit ? 0.5 : 2.0,
			ProtectionLevel::Relaxed => $this === self::Limit ? 2.0 : 0.5,
			ProtectionLevel::Recommended, ProtectionLevel::Custom => 1.0,
		};
	}
}
