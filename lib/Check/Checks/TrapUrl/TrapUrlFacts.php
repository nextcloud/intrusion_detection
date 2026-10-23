<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\TrapUrl;

use OCA\IntrusionDetection\Detection\CommonFacts;
use OCA\IntrusionDetection\Detection\FactValues;
use OCA\IntrusionDetection\Detection\IMergeableFacts;

/**
 * What a trap URL detection recorded: the trap path an address requested.
 */
final readonly class TrapUrlFacts implements IMergeableFacts {
	/**
	 * @param string $path the requested path, shortened
	 * @param string $trap the trap it matched
	 * @param ?string $method the request method
	 */
	public function __construct(
		public string $path = '',
		public string $trap = '',
		public ?string $method = null,
		public CommonFacts $common = new CommonFacts(),
	) {
	}

	/**
	 * @param array<array-key, mixed> $stored
	 */
	public static function fromArray(array $stored): self {
		return new self(
			FactValues::string($stored, 'path') ?? '',
			FactValues::string($stored, 'trap') ?? '',
			FactValues::string($stored, 'method'),
			CommonFacts::fromArray($stored),
		);
	}

	#[\Override]
	public function toArray(): array {
		return [
			'path' => $this->path,
			'trap' => $this->trap,
		] + FactValues::recorded([
			'method' => $this->method,
		]) + $this->common->toArray();
	}

	/**
	 * Everything is the latest.
	 */
	public static function merge(self $old, self $new): self {
		return new self(
			$new->path,
			$new->trap,
			$new->method ?? $old->method,
			CommonFacts::merge($old->common, $new->common),
		);
	}

	#[\Override]
	public function mergedOnto(array $stored): array {
		return array_replace($stored, self::merge(self::fromArray($stored), $this)->toArray());
	}
}
