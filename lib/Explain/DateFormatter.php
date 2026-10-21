<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Explain;

use OCP\IDateTimeFormatter;
use OCP\IL10N;

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

	/**
	 * Date and time for a reader other than the current user, e.g. in an
	 * email: in their time zone and language.
	 */
	public function dateTimeFor(int $timestamp, \DateTimeZone $timeZone, IL10N $l): string {
		return $this->formatter->formatDateTime($timestamp, 'long', 'short', $timeZone, $l);
	}
}
