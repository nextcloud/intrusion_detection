<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Config;

/**
 * The protection level: one choice that sets the limits of every check and
 * the block durations together. It never changes a check's mode or
 * responses. "Custom" means an administrator changed a limit by hand.
 */
enum ProtectionLevel: string {
	/** The defaults */
	case Recommended = 'recommended';
	/** Count limits halved, blocks twice as long */
	case Strict = 'strict';
	/** Count limits doubled, blocks half as long */
	case Relaxed = 'relaxed';
	case Custom = 'custom';

	/**
	 * The levels an administrator can choose, from the loosest to the
	 * tightest limits; Custom only results from changes by hand.
	 *
	 * @return list<self>
	 */
	public static function choosable(): array {
		return [self::Relaxed, self::Recommended, self::Strict];
	}
}
