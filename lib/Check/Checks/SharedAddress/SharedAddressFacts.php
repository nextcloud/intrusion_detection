<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\SharedAddress;

use OCA\IntrusionDetection\Detection\CommonFacts;
use OCA\IntrusionDetection\Detection\FactValues;
use OCA\IntrusionDetection\Detection\IMergeableFacts;

/**
 * What a shared address detection recorded: the address many accounts log
 * in from that the safety valve kept from being blocked.
 */
final readonly class SharedAddressFacts implements IMergeableFacts {
	/**
	 * @param int $users the accounts that logged in from it
	 * @param string $wantedBy the check that wanted to block it
	 * @param ?bool $proxy true when it looks like a reverse proxy without trusted_proxies
	 */
	public function __construct(
		public int $users = 0,
		public string $wantedBy = '',
		public ?bool $proxy = null,
		public CommonFacts $common = new CommonFacts(),
	) {
	}

	/**
	 * @param array<array-key, mixed> $stored
	 */
	public static function fromArray(array $stored): self {
		return new self(
			FactValues::int($stored, 'users') ?? 0,
			FactValues::string($stored, 'wantedBy') ?? '',
			FactValues::bool($stored, 'proxy'),
			CommonFacts::fromArray($stored),
		);
	}

	#[\Override]
	public function toArray(): array {
		return [
			'users' => $this->users,
			'wantedBy' => $this->wantedBy,
		] + FactValues::recorded([
			'proxy' => $this->proxy,
		]) + $this->common->toArray();
	}

	/**
	 * Everything is the latest.
	 */
	public static function merge(self $old, self $new): self {
		return new self(
			$new->users,
			$new->wantedBy,
			$new->proxy ?? $old->proxy,
			CommonFacts::merge($old->common, $new->common),
		);
	}

	#[\Override]
	public function mergedOnto(array $stored): array {
		return array_replace($stored, self::merge(self::fromArray($stored), $this)->toArray());
	}
}
