<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\InjectionProbe;

use OCA\IntrusionDetection\Detection\CommonFacts;
use OCA\IntrusionDetection\Detection\FactsMerger;
use OCA\IntrusionDetection\Detection\FactValues;
use OCA\IntrusionDetection\Detection\IMergeableFacts;

/**
 * What an injection probe detection recorded: where in the request the
 * signatures matched, and an excerpt. Never the full request, and never
 * anything from a parameter that is not inspected.
 */
final readonly class InjectionProbeFacts implements IMergeableFacts {
	/**
	 * @param string $location where it matched, one of PayloadHit::LOCATION_*
	 * @param string $param the parameter name ('' for the path)
	 * @param list<string> $signatures the ids of the signatures that matched
	 * @param array<string, int> $weights signature id => weight
	 * @param int $weight their total weight
	 * @param int $minWeight the weight that was needed
	 * @param string $encoding how the value was hidden, one of FormMatch::ENCODING_*
	 * @param string $excerpt the suspicious part
	 * @param list<string> $otherParams further parameters that matched too
	 * @param int $signaturesVersion the version of the built-in signatures
	 * @param bool $authenticated the request was logged in
	 * @param ?string $credential what the request carried if it claimed to be logged in, one of PendingHit::CREDENTIAL_*
	 */
	public function __construct(
		public string $location = '',
		public string $param = '',
		public array $signatures = [],
		public array $weights = [],
		public int $weight = 0,
		public int $minWeight = 0,
		public string $encoding = FormMatch::ENCODING_NONE,
		public string $excerpt = '',
		public array $otherParams = [],
		public int $signaturesVersion = 0,
		public bool $authenticated = false,
		public ?string $credential = null,
		public CommonFacts $common = new CommonFacts(),
	) {
	}

	/**
	 * @param array<array-key, mixed> $stored
	 */
	public static function fromArray(array $stored): self {
		return new self(
			FactValues::string($stored, 'location') ?? '',
			FactValues::string($stored, 'param') ?? '',
			FactValues::strings($stored, 'signatures') ?? [],
			self::weights(FactValues::array($stored, 'weights')),
			FactValues::int($stored, 'weight') ?? 0,
			FactValues::int($stored, 'minWeight') ?? 0,
			FactValues::string($stored, 'encoding') ?? FormMatch::ENCODING_NONE,
			FactValues::string($stored, 'excerpt') ?? '',
			FactValues::strings($stored, 'otherParams') ?? [],
			FactValues::int($stored, 'signaturesVersion') ?? 0,
			FactValues::bool($stored, 'authenticated') ?? false,
			FactValues::string($stored, 'credential'),
			CommonFacts::fromArray($stored),
		);
	}

	#[\Override]
	public function toArray(): array {
		return [
			'location' => $this->location,
			'param' => $this->param,
			'signatures' => $this->signatures,
			'weights' => $this->weights,
			'weight' => $this->weight,
			'minWeight' => $this->minWeight,
			'encoding' => $this->encoding,
			'excerpt' => $this->excerpt,
			'otherParams' => $this->otherParams,
			'signaturesVersion' => $this->signaturesVersion,
			'authenticated' => $this->authenticated,
			'credential' => $this->credential,
		] + $this->common->toArray();
	}

	/**
	 * The signatures and parameters of every hit; the rest is the latest.
	 */
	public static function merge(self $old, self $new): self {
		return new self(
			$new->location,
			$new->param,
			FactsMerger::union($old->signatures, $new->signatures) ?? [],
			$new->weights,
			$new->weight,
			$new->minWeight,
			$new->encoding,
			$new->excerpt,
			FactsMerger::union($old->otherParams, $new->otherParams) ?? [],
			$new->signaturesVersion,
			$new->authenticated,
			$new->credential,
			CommonFacts::merge($old->common, $new->common),
		);
	}

	#[\Override]
	public function mergedOnto(array $stored): array {
		return array_replace($stored, self::merge(self::fromArray($stored), $this)->toArray());
	}

	/**
	 * @param ?array<array-key, mixed> $weights
	 * @return array<string, int>
	 */
	private static function weights(?array $weights): array {
		$typed = [];
		foreach ($weights ?? [] as $id => $weight) {
			$typed[(string)$id] = (int)$weight;
		}
		return $typed;
	}
}
