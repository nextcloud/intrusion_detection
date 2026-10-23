<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\StepUpUnconfirmed;

use OCA\IntrusionDetection\Detection\CommonFacts;
use OCA\IntrusionDetection\Detection\FactsMerger;
use OCA\IntrusionDetection\Detection\FactValues;
use OCA\IntrusionDetection\Detection\IMergeableFacts;

/**
 * What a login allowed without confirmation recorded: why it needed one,
 * who logged in, and what the policies of its reasons asked for.
 */
final readonly class StepUpUnconfirmedFacts implements IMergeableFacts {
	/**
	 * @param list<string> $policies why the login needed confirmation ({@see \OCA\IntrusionDetection\Confirm\StepUpPolicy})
	 * @param bool $client an app or script sent the password
	 * @param bool $notify tell the user and the administrators
	 * @param bool $forceChange require a new password
	 */
	public function __construct(
		public array $policies = [],
		public bool $client = false,
		public bool $notify = false,
		public bool $forceChange = false,
		public CommonFacts $common = new CommonFacts(),
	) {
	}

	/**
	 * @param array<array-key, mixed> $stored
	 */
	public static function fromArray(array $stored): self {
		return new self(
			FactValues::strings($stored, 'policies') ?? [],
			FactValues::bool($stored, 'client') ?? false,
			FactValues::bool($stored, 'notify') ?? false,
			FactValues::bool($stored, 'forceChange') ?? false,
			CommonFacts::fromArray($stored),
		);
	}

	#[\Override]
	public function toArray(): array {
		return [
			'policies' => $this->policies,
			'client' => $this->client,
			'notify' => $this->notify,
			'forceChange' => $this->forceChange,
		] + $this->common->toArray();
	}

	/**
	 * The reasons of every hit; the rest is the latest.
	 */
	public static function merge(self $old, self $new): self {
		return new self(
			FactsMerger::union($old->policies, $new->policies) ?? [],
			$new->client,
			$new->notify,
			$new->forceChange,
			CommonFacts::merge($old->common, $new->common),
		);
	}

	#[\Override]
	public function mergedOnto(array $stored): array {
		return array_replace($stored, self::merge(self::fromArray($stored), $this)->toArray());
	}
}
