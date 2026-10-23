<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\LoginFlowMismatch;

use OCA\IntrusionDetection\Detection\CommonFacts;
use OCA\IntrusionDetection\Detection\FactValues;
use OCA\IntrusionDetection\Detection\IFacts;

/**
 * What a login flow mismatch detection recorded: where a login request for
 * a new device was started and approved, and how long it took.
 */
final readonly class LoginFlowMismatchFacts implements IFacts {
	/**
	 * @param ?string $initiator the address that started the request, if known
	 * @param string $granter the address that approved it
	 * @param int $age the seconds between the two
	 * @param int $startedAt when it was started
	 * @param string $client the name of the new device
	 * @param ?int $tokenId the id of the app password it got
	 * @param bool $trusted it was started in a network the person confirmed as their own
	 */
	public function __construct(
		public ?LoginFlowMismatchRule $rule = null,
		public ?string $initiator = null,
		public string $granter = '',
		public int $age = 0,
		public int $startedAt = 0,
		public string $client = '',
		public ?int $tokenId = null,
		public bool $trusted = false,
		public CommonFacts $common = new CommonFacts(),
	) {
	}

	/**
	 * @param array<array-key, mixed> $stored
	 */
	public static function fromArray(array $stored): self {
		return new self(
			LoginFlowMismatchRule::tryFrom((string)FactValues::string($stored, 'rule')),
			FactValues::string($stored, 'initiator'),
			FactValues::string($stored, 'granter') ?? '',
			FactValues::int($stored, 'age') ?? 0,
			FactValues::int($stored, 'startedAt') ?? 0,
			FactValues::string($stored, 'client') ?? '',
			FactValues::int($stored, 'tokenId'),
			FactValues::bool($stored, 'trusted') ?? false,
			CommonFacts::fromArray($stored),
		);
	}

	#[\Override]
	public function toArray(): array {
		return [
			'initiator' => $this->initiator,
			'granter' => $this->granter,
			'age' => $this->age,
			'startedAt' => $this->startedAt,
			'client' => $this->client,
			'tokenId' => $this->tokenId,
			'trusted' => $this->trusted,
		] + FactValues::recorded([
			'rule' => $this->rule?->value,
		]) + $this->common->toArray();
	}
}
