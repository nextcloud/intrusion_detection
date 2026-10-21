<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Explain;

use OCP\IDateTimeFormatter;
use OCP\IL10N;
use Psr\Container\ContainerInterface;

/**
 * Formats timestamps for explanations, in the reader's time zone.
 *
 * The reader is the current user, unless a text for someone else, such as
 * an email, is built within {@see forReader()}.
 *
 * Core's formatter is resolved on the first use: it takes the time zone and
 * language of the session, so it must not be built while a check is
 * constructed, which may happen before the session exists.
 */
class DateFormatter {
	private ?IDateTimeFormatter $formatter = null;
	private ?\DateTimeZone $timeZone = null;
	private ?IL10N $l = null;

	public function __construct(
		private readonly ?ContainerInterface $container = null,
	) {
	}

	/**
	 * A formatter that uses the given one, for tests and callers that have one.
	 */
	public static function using(IDateTimeFormatter $formatter): self {
		$dates = new self();
		$dates->formatter = $formatter;
		return $dates;
	}

	/**
	 * Date and time in the one style of the server's texts, e.g. "October 21, 2026, 6:10 PM".
	 */
	public function dateTime(int $timestamp): string {
		return $this->formatter()->formatDateTime($timestamp, 'long', 'short', $this->timeZone, $this->l);
	}

	/**
	 * How long ago, e.g. "4 minutes ago", for lists that are read now.
	 */
	public function ago(int $timestamp, int $now): string {
		return $this->formatter()->formatTimeSpan($timestamp, $now, $this->l);
	}

	public function time(int $timestamp): string {
		return $this->formatter()->formatTime($timestamp, 'short', $this->timeZone, $this->l);
	}

	/**
	 * Runs `$build` with every date and time in the given time zone, and in
	 * the language and locale of `$l`, for a text read by someone other than
	 * the current user. Scopes can be nested.
	 *
	 * @template T
	 * @param \Closure(): T $build
	 * @return T
	 */
	public function forReader(\DateTimeZone $timeZone, IL10N $l, \Closure $build): mixed {
		$previous = [$this->timeZone, $this->l];
		$this->timeZone = $timeZone;
		$this->l = $l;
		try {
			return $build();
		} finally {
			[$this->timeZone, $this->l] = $previous;
		}
	}

	private function formatter(): IDateTimeFormatter {
		if ($this->formatter === null) {
			$formatter = $this->container?->get(IDateTimeFormatter::class);
			if (!$formatter instanceof IDateTimeFormatter) {
				throw new \LogicException('No date formatter');
			}
			$this->formatter = $formatter;
		}
		return $this->formatter;
	}
}
