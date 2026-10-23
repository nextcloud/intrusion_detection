<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Address;

use OCA\IntrusionDetection\Login\RequestContext;

/**
 * What the app knows about one client address: whether it is blocked, and
 * which network attributes it has (hosting, tor, observed blocklist matches).
 *
 * Kept small, because one verdict per address lives in the memory cache.
 */
final class Verdict {
	/** The request context key of the verdict a guard resolved in this request */
	public const CONTEXT_KEY = 'address.verdict';

	/**
	 * @param int $denyUntil timestamp until which the address is blocked, 0 if it is not
	 * @param string $reference the block reference shown to the client
	 * @param list<string> $attributes network attributes, e.g. "hosting", "tor", "list:spamhaus_drop"
	 * @param int $cacheUntil when this verdict must be re-resolved at the latest
	 * @param bool $perAddress whether it holds for this IPv6 address only, not for its whole /64
	 */
	public function __construct(
		public readonly int $denyUntil = 0,
		public readonly string $reference = '',
		public readonly array $attributes = [],
		public readonly int $cacheUntil = 0,
		public readonly bool $perAddress = false,
	) {
	}

	/**
	 * The address verdict, if a guard resolved it in this request.
	 */
	public static function of(RequestContext $context): ?self {
		$verdict = $context->get(self::CONTEXT_KEY);
		return $verdict instanceof self ? $verdict : null;
	}

	public function isDenied(int $now): bool {
		return $this->denyUntil > $now;
	}

	public function hasAttribute(string $attribute): bool {
		return in_array($attribute, $this->attributes, true);
	}

	/**
	 * @return array{u: int, r: string, a: list<string>, c: int, x?: true}
	 */
	public function toArray(): array {
		$data = ['u' => $this->denyUntil, 'r' => $this->reference, 'a' => $this->attributes, 'c' => $this->cacheUntil];
		if ($this->perAddress) {
			$data['x'] = true;
		}
		return $data;
	}

	public static function fromArray(mixed $data): ?self {
		if (!is_array($data) || !isset($data['u'], $data['r'], $data['a'], $data['c'])
			|| !is_int($data['u']) || !is_string($data['r']) || !is_array($data['a']) || !is_int($data['c'])) {
			return null;
		}
		return new self($data['u'], $data['r'], array_values(array_filter($data['a'], 'is_string')), $data['c'], ($data['x'] ?? false) === true);
	}
}
