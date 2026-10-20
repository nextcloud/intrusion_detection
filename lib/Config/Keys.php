<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Config;

/**
 * Names of the per-check config keys. Config keys may only contain letters,
 * digits and underscores, and are at most 64 characters long.
 */
final class Keys {
	public static function mode(string $checkId): string {
		return 'check_' . $checkId . '_mode';
	}

	public static function responses(string $checkId): string {
		return 'check_' . $checkId . '_responses';
	}

	public static function param(string $checkId, string $param): string {
		return 'check_' . $checkId . '_' . $param;
	}
}
