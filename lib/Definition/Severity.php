<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Definition;

enum Severity: string {
	case Low = 'low';
	case Medium = 'medium';
	case High = 'high';
	case Critical = 'critical';

	public function rank(): int {
		return match ($this) {
			self::Low => 1,
			self::Medium => 2,
			self::High => 3,
			self::Critical => 4,
		};
	}

	public function atLeast(self $other): bool {
		return $this->rank() >= $other->rank();
	}
}
