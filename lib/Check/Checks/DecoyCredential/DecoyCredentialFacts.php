<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\DecoyCredential;

use OCA\IntrusionDetection\Detection\CommonFacts;
use OCA\IntrusionDetection\Detection\FactValues;
use OCA\IntrusionDetection\Detection\IMergeableFacts;

/**
 * What a decoy credential detection recorded: the decoy, and whether its
 * secret or only its login name was used. Never the secret.
 */
final readonly class DecoyCredentialFacts implements IMergeableFacts {
	/**
	 * @param int $decoy the id of the decoy
	 * @param string $label its label
	 * @param string $format the format of its secret
	 */
	public function __construct(
		public int $decoy = 0,
		public string $label = '',
		public string $format = '',
		public ?DecoyCredentialMatch $match = null,
		public CommonFacts $common = new CommonFacts(),
	) {
	}

	/**
	 * @param array<array-key, mixed> $stored
	 */
	public static function fromArray(array $stored): self {
		return new self(
			FactValues::int($stored, 'decoy') ?? 0,
			FactValues::string($stored, 'label') ?? '',
			FactValues::string($stored, 'format') ?? '',
			DecoyCredentialMatch::tryFrom((string)FactValues::string($stored, 'match')),
			CommonFacts::fromArray($stored),
		);
	}

	#[\Override]
	public function toArray(): array {
		return [
			'decoy' => $this->decoy,
			'label' => $this->label,
			'format' => $this->format,
		] + FactValues::recorded([
			'match' => $this->match?->value,
		]) + $this->common->toArray();
	}

	/**
	 * Everything is the latest: a later use of the secret is the stronger
	 * sign.
	 */
	public static function merge(self $old, self $new): self {
		return new self(
			$new->decoy,
			$new->label,
			$new->format,
			$new->match ?? $old->match,
			CommonFacts::merge($old->common, $new->common),
		);
	}

	#[\Override]
	public function mergedOnto(array $stored): array {
		return array_replace($stored, self::merge(self::fromArray($stored), $this)->toArray());
	}
}
