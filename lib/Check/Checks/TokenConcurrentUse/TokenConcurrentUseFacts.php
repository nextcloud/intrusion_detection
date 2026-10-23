<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\TokenConcurrentUse;

use OCA\IntrusionDetection\Detection\CommonFacts;
use OCA\IntrusionDetection\Detection\FactValues;
use OCA\IntrusionDetection\Detection\IMergeableFacts;

/**
 * What a concurrent use detection recorded: the two networks one
 * credential was used from, and how often it switched between them.
 */
final readonly class TokenConcurrentUseFacts implements IMergeableFacts {
	/**
	 * @param string $ip1 the address it was used from before
	 * @param string $net1 its network
	 * @param string $ip2 the address it was used from at the switch
	 * @param string $net2 its network
	 * @param int $family the IP family, 4 or 6
	 * @param int $switches the switches between the two within the window
	 * @param string $kind the credential, one of TokenConcurrentUse::KIND_*
	 * @param string $scheme how it was sent
	 * @param string $tokenName the name of the app password or session
	 * @param ?int $tokenId the id of the app password or token
	 * @param ?int $sessionTokenId the id of the session token
	 */
	public function __construct(
		public string $ip1 = '',
		public string $net1 = '',
		public string $ip2 = '',
		public string $net2 = '',
		public int $family = 0,
		public int $switches = 0,
		public string $kind = '',
		public string $scheme = '',
		public string $tokenName = '',
		public ?int $tokenId = null,
		public ?int $sessionTokenId = null,
		public CommonFacts $common = new CommonFacts(),
	) {
	}

	/**
	 * @param array<array-key, mixed> $stored
	 */
	public static function fromArray(array $stored): self {
		return new self(
			FactValues::string($stored, 'ip1') ?? '',
			FactValues::string($stored, 'net1') ?? '',
			FactValues::string($stored, 'ip2') ?? '',
			FactValues::string($stored, 'net2') ?? '',
			FactValues::int($stored, 'family') ?? 0,
			FactValues::int($stored, 'switches') ?? 0,
			FactValues::string($stored, 'kind') ?? '',
			FactValues::string($stored, 'scheme') ?? '',
			FactValues::string($stored, 'tokenName') ?? '',
			FactValues::int($stored, 'tokenId'),
			FactValues::int($stored, 'sessionTokenId'),
			CommonFacts::fromArray($stored),
		);
	}

	#[\Override]
	public function toArray(): array {
		return [
			'ip1' => $this->ip1,
			'net1' => $this->net1,
			'ip2' => $this->ip2,
			'net2' => $this->net2,
			'family' => $this->family,
			'switches' => $this->switches,
			'kind' => $this->kind,
			'scheme' => $this->scheme,
			'tokenName' => $this->tokenName,
			'tokenId' => $this->tokenId,
			'sessionTokenId' => $this->sessionTokenId,
		] + $this->common->toArray();
	}

	/**
	 * Everything is the latest.
	 */
	public static function merge(self $old, self $new): self {
		return new self(
			$new->ip1,
			$new->net1,
			$new->ip2,
			$new->net2,
			$new->family,
			$new->switches,
			$new->kind,
			$new->scheme,
			$new->tokenName,
			$new->tokenId,
			$new->sessionTokenId,
			CommonFacts::merge($old->common, $new->common),
		);
	}

	#[\Override]
	public function mergedOnto(array $stored): array {
		return array_replace($stored, self::merge(self::fromArray($stored), $this)->toArray());
	}
}
