<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\CredentialStuffing;

use OCA\IntrusionDetection\Detection\CommonFacts;
use OCA\IntrusionDetection\Detection\FactValues;
use OCA\IntrusionDetection\Detection\IMergeableFacts;

/**
 * What a credential stuffing detection recorded: the failed logins of an
 * address, of its network, or of the whole server.
 */
final readonly class CredentialStuffingFacts implements IMergeableFacts {
	/**
	 * @param int $failures the failed logins within the window
	 * @param int $names the login names they tried
	 * @param int $sources the addresses they came from
	 * @param ?string $net the IPv4 /24 of a network detection
	 * @param ?bool $distributed true for an attack spread over the whole server
	 */
	public function __construct(
		public ?CredentialStuffingRule $rule = null,
		public int $failures = 0,
		public int $names = 0,
		public int $sources = 0,
		public ?string $net = null,
		public ?bool $distributed = null,
		public CommonFacts $common = new CommonFacts(),
	) {
	}

	/**
	 * @param array<array-key, mixed> $stored
	 */
	public static function fromArray(array $stored): self {
		return new self(
			CredentialStuffingRule::tryFrom((string)FactValues::string($stored, 'rule')),
			FactValues::int($stored, 'failures') ?? 0,
			FactValues::int($stored, 'names') ?? 0,
			FactValues::int($stored, 'sources') ?? 0,
			FactValues::string($stored, 'net'),
			FactValues::bool($stored, 'distributed'),
			CommonFacts::fromArray($stored),
		);
	}

	#[\Override]
	public function toArray(): array {
		return [
			'failures' => $this->failures,
			'names' => $this->names,
			'sources' => $this->sources,
		] + FactValues::recorded([
			'rule' => $this->rule?->value,
			'net' => $this->net,
			'distributed' => $this->distributed,
		]) + $this->common->toArray();
	}

	/**
	 * The rule stays, the counts are the latest.
	 */
	public static function merge(self $old, self $new): self {
		return new self(
			$old->rule ?? $new->rule,
			$new->failures,
			$new->names,
			$new->sources,
			$new->net ?? $old->net,
			$new->distributed ?? $old->distributed,
			CommonFacts::merge($old->common, $new->common),
		);
	}

	#[\Override]
	public function mergedOnto(array $stored): array {
		return array_replace($stored, self::merge(self::fromArray($stored), $this)->toArray());
	}
}
