<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\StepUpRefusedClient;

use OCA\IntrusionDetection\Detection\CommonFacts;
use OCA\IntrusionDetection\Detection\FactsMerger;
use OCA\IntrusionDetection\Detection\FactValues;
use OCA\IntrusionDetection\Detection\IMergeableFacts;

/**
 * What a refused app login recorded: why it needed confirmation, and
 * whether the account could have confirmed it in a browser.
 */
final readonly class StepUpRefusedClientFacts implements IMergeableFacts {
	/**
	 * @param list<string> $policies why the login needed confirmation ({@see \OCA\IntrusionDetection\Confirm\StepUpPolicy})
	 * @param ?bool $inBrowser the account could confirm such a login in a browser
	 */
	public function __construct(
		public array $policies = [],
		public ?bool $inBrowser = null,
		public CommonFacts $common = new CommonFacts(),
	) {
	}

	/**
	 * @param array<array-key, mixed> $stored
	 */
	public static function fromArray(array $stored): self {
		return new self(
			FactValues::strings($stored, 'policies') ?? [],
			FactValues::bool($stored, 'inBrowser'),
			CommonFacts::fromArray($stored),
		);
	}

	#[\Override]
	public function toArray(): array {
		return [
			'policies' => $this->policies,
		] + FactValues::recorded([
			'inBrowser' => $this->inBrowser,
		]) + $this->common->toArray();
	}

	/**
	 * The reasons of every hit; the rest is the latest.
	 */
	public static function merge(self $old, self $new): self {
		return new self(
			FactsMerger::union($old->policies, $new->policies) ?? [],
			$new->inBrowser ?? $old->inBrowser,
			CommonFacts::merge($old->common, $new->common),
		);
	}

	#[\Override]
	public function mergedOnto(array $stored): array {
		return array_replace($stored, self::merge(self::fromArray($stored), $this)->toArray());
	}
}
