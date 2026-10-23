<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\UserDenied;

use OCA\IntrusionDetection\Detection\CommonFacts;
use OCA\IntrusionDetection\Detection\FactValues;
use OCA\IntrusionDetection\Detection\IMergeableFacts;

/**
 * What a "No, it was not me" detection recorded: the detection the account
 * holder answered, and what the answer may end.
 */
final readonly class UserDeniedFacts implements IMergeableFacts {
	/**
	 * @param int $detection the id of the answered detection
	 * @param string $check its check
	 * @param ?int $detectedAt when it was detected
	 * @param bool $passwordInvolved the password was involved
	 * @param bool $answeredFromSource the answer came from the address of the event
	 * @param ?string $network the network whose logins need extra confirmation
	 * @param bool $weakSession the answer came from a session whose login proved no more than the password
	 * @param ?int $tokenId the app password the answer revokes
	 */
	public function __construct(
		public int $detection = 0,
		public string $check = '',
		public ?int $detectedAt = null,
		public bool $passwordInvolved = false,
		public bool $answeredFromSource = false,
		public ?string $network = null,
		public bool $weakSession = false,
		public ?int $tokenId = null,
		public CommonFacts $common = new CommonFacts(),
	) {
	}

	/**
	 * @param array<array-key, mixed> $stored
	 */
	public static function fromArray(array $stored): self {
		return new self(
			FactValues::int($stored, 'detection') ?? 0,
			FactValues::string($stored, 'check') ?? '',
			FactValues::int($stored, 'detectedAt'),
			FactValues::bool($stored, 'passwordInvolved') ?? false,
			FactValues::bool($stored, 'answeredFromSource') ?? false,
			FactValues::string($stored, 'network'),
			FactValues::bool($stored, 'weakSession') ?? false,
			FactValues::int($stored, 'tokenId'),
			CommonFacts::fromArray($stored),
		);
	}

	#[\Override]
	public function toArray(): array {
		return [
			'detection' => $this->detection,
			'check' => $this->check,
			'passwordInvolved' => $this->passwordInvolved,
			'answeredFromSource' => $this->answeredFromSource,
			'network' => $this->network,
			'weakSession' => $this->weakSession,
			'tokenId' => $this->tokenId,
		] + FactValues::recorded([
			'detectedAt' => $this->detectedAt,
		]) + $this->common->toArray();
	}

	/**
	 * The sessions of every answer; the rest is the latest.
	 */
	public static function merge(self $old, self $new): self {
		return new self(
			$new->detection,
			$new->check,
			$new->detectedAt ?? $old->detectedAt,
			$new->passwordInvolved,
			$new->answeredFromSource,
			$new->network,
			$new->weakSession,
			$new->tokenId,
			CommonFacts::merge($old->common, $new->common),
		);
	}

	#[\Override]
	public function mergedOnto(array $stored): array {
		return array_replace($stored, self::merge(self::fromArray($stored), $this)->toArray());
	}
}
