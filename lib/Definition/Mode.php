<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Definition;

use OCP\IL10N;

/**
 * How a check runs: not at all, recording only, or acting.
 */
enum Mode: string {
	case Off = 'off';
	case Observe = 'observe';
	case Protect = 'protect';

	public function runs(): bool {
		return $this !== self::Off;
	}

	public function acts(): bool {
		return $this === self::Protect;
	}

	public function label(IL10N $l): string {
		return match ($this) {
			self::Off => $l->t('Off'),
			self::Observe => $l->t('Observe'),
			self::Protect => $l->t('Protect'),
		};
	}
}
