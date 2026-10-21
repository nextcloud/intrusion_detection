<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Incident;

use OCP\IL10N;

/**
 * The subject or the period of an incident report was not valid.
 */
final class InvalidIncidentQuery extends \InvalidArgumentException {
	public const INVALID_USER = 'invalid_user';
	public const INVALID_ADDRESS = 'invalid_address';
	public const INVALID_RANGE = 'invalid_range';
	public const RANGE_ORDER = 'range_order';
	public const RANGE_TOO_LONG = 'range_too_long';
	public const SUBJECT = 'subject';

	public function __construct(
		public readonly string $reason,
	) {
		parent::__construct($reason);
	}

	/**
	 * The field the problem is about, for the admin page.
	 */
	public function param(): string {
		return match ($this->reason) {
			self::INVALID_USER => 'user',
			self::INVALID_ADDRESS => 'address',
			self::SUBJECT => 'subject',
			default => 'since',
		};
	}

	public function describe(IL10N $l): string {
		return match ($this->reason) {
			self::INVALID_USER => $l->t('Choose an account.'),
			self::INVALID_ADDRESS => $l->t('Enter a single IPv4 or IPv6 address, for example 203.0.113.7.'),
			self::RANGE_ORDER => $l->t('The start of the period must be before its end.'),
			self::RANGE_TOO_LONG => $l->t('A report covers at most %s days. Choose a shorter period.', [(string)intdiv(IncidentQuery::MAX_PERIOD, 86400)]),
			self::SUBJECT => $l->t('Choose either an account or an address.'),
			default => $l->t('The period is not valid.'),
		};
	}
}
