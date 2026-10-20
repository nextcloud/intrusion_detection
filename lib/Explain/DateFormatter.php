<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Explain;

use OCP\IDateTimeFormatter;

/**
 * Formats timestamps for explanations, in the reader's time zone.
 */
class DateFormatter {
	public function __construct(
		private readonly IDateTimeFormatter $formatter,
	) {
	}

	public function dateTime(int $timestamp): string {
		return $this->formatter->formatDateTime($timestamp, 'short', 'short');
	}

	public function time(int $timestamp): string {
		return $this->formatter->formatTime($timestamp, 'short');
	}
}
