<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Incident;

use OCA\IntrusionDetection\Net\SourceKey;

/**
 * What an incident report is about: one account or one address, and a
 * period. Built only through {@see self::forUser()} and
 * {@see self::forAddress()}, which validate the input.
 *
 * Sources return at most `$limit` entries each, oldest first; the report
 * builder sets the limit.
 */
final class IncidentQuery {
	public const SUBJECT_USER = 'user';
	public const SUBJECT_ADDRESS = 'address';

	/** The default period: the seven days before now */
	public const DEFAULT_PERIOD = 7 * 86400;
	/** The longest period one report covers; detections are kept 90 days by default */
	public const MAX_PERIOD = 90 * 86400;
	private const DEFAULT_LIMIT = 100;
	/** The longest account name, as in core's tables */
	private const MAX_UID_LENGTH = 64;

	private function __construct(
		public readonly string $subjectType,
		public readonly ?string $uid,
		public readonly ?SourceKey $address,
		public readonly int $since,
		public readonly int $until,
		public readonly int $limit,
	) {
	}

	/**
	 * @param ?int $since start of the period; null for the default period before $until
	 * @param ?int $until end of the period; null for now
	 * @throws InvalidIncidentQuery
	 */
	public static function forUser(string $uid, ?int $since, ?int $until, int $now): self {
		$uid = trim($uid);
		if ($uid === '' || mb_strlen($uid) > self::MAX_UID_LENGTH || preg_match('/[\x00-\x1f\x7f]/', $uid) === 1) {
			throw new InvalidIncidentQuery(InvalidIncidentQuery::INVALID_USER);
		}
		[$since, $until] = self::range($since, $until, $now);
		return new self(self::SUBJECT_USER, $uid, null, $since, $until, self::DEFAULT_LIMIT);
	}

	/**
	 * @throws InvalidIncidentQuery
	 */
	public static function forAddress(string $address, ?int $since, ?int $until, int $now): self {
		$source = SourceKey::tryFromIp($address);
		if ($source === null) {
			throw new InvalidIncidentQuery(InvalidIncidentQuery::INVALID_ADDRESS);
		}
		[$since, $until] = self::range($since, $until, $now);
		return new self(self::SUBJECT_ADDRESS, null, $source, $since, $until, self::DEFAULT_LIMIT);
	}

	public function withLimit(int $limit): self {
		return new self($this->subjectType, $this->uid, $this->address, $this->since, $this->until, max(1, $limit));
	}

	public function isUser(): bool {
		return $this->subjectType === self::SUBJECT_USER;
	}

	/**
	 * The account or the address, as people read it.
	 */
	public function subject(): string {
		return $this->uid ?? $this->address?->ip ?? '';
	}

	/**
	 * @return array{0: int, 1: int}
	 * @throws InvalidIncidentQuery
	 */
	private static function range(?int $since, ?int $until, int $now): array {
		$until ??= $now;
		$since ??= $until - self::DEFAULT_PERIOD;
		if ($since < 0 || $until < 0) {
			throw new InvalidIncidentQuery(InvalidIncidentQuery::INVALID_RANGE);
		}
		if ($since >= $until) {
			throw new InvalidIncidentQuery(InvalidIncidentQuery::RANGE_ORDER);
		}
		if ($until - $since > self::MAX_PERIOD) {
			throw new InvalidIncidentQuery(InvalidIncidentQuery::RANGE_TOO_LONG);
		}
		return [$since, $until];
	}
}
