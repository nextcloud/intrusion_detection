<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\SecondFactorFailed;

use OCA\IntrusionDetection\Detection\CommonFacts;
use OCA\IntrusionDetection\Detection\FactsMerger;
use OCA\IntrusionDetection\Detection\FactValues;
use OCA\IntrusionDetection\Detection\IMergeableFacts;

/**
 * What a second factor failure detection recorded: the provider, the
 * failures in the login and within the hour, and the rules they reached.
 */
final readonly class SecondFactorFailedFacts implements IMergeableFacts {
	/**
	 * @param string $provider the id of the second-factor provider
	 * @param ?string $providerName its name
	 * @param int $loginFailures the failures in that login
	 * @param int $hourFailures the failures for the account within the hour
	 * @param list<SecondFactorFailedRule> $rules the rules the failure reached
	 * @param ?string $flag why the address was flagged before, if it was
	 * @param ?int $sessionTokenId the session of the login
	 */
	public function __construct(
		public string $provider = '',
		public ?string $providerName = null,
		public int $loginFailures = 0,
		public int $hourFailures = 0,
		public array $rules = [],
		public ?string $flag = null,
		public ?int $sessionTokenId = null,
		public CommonFacts $common = new CommonFacts(),
	) {
	}

	/**
	 * @param array<array-key, mixed> $stored
	 */
	public static function fromArray(array $stored): self {
		return new self(
			FactValues::string($stored, 'provider') ?? '',
			FactValues::string($stored, 'providerName'),
			FactValues::int($stored, 'loginFailures') ?? 0,
			FactValues::int($stored, 'hourFailures') ?? 0,
			array_values(array_filter(array_map(static fn (string $rule): ?SecondFactorFailedRule => SecondFactorFailedRule::tryFrom($rule), FactValues::strings($stored, 'rules') ?? []))),
			FactValues::string($stored, 'flag'),
			FactValues::int($stored, 'sessionTokenId'),
			CommonFacts::fromArray($stored),
		);
	}

	#[\Override]
	public function toArray(): array {
		return [
			'provider' => $this->provider,
			'loginFailures' => $this->loginFailures,
			'hourFailures' => $this->hourFailures,
			'rules' => array_map(static fn (SecondFactorFailedRule $rule): string => $rule->value, $this->rules),
			'flag' => $this->flag,
			'sessionTokenId' => $this->sessionTokenId,
		] + FactValues::recorded([
			'providerName' => $this->providerName,
		]) + $this->common->toArray();
	}

	/**
	 * The rules of every hit; the rest is the latest.
	 */
	public static function merge(self $old, self $new): self {
		return new self(
			$new->provider,
			$new->providerName ?? $old->providerName,
			$new->loginFailures,
			$new->hourFailures,
			FactsMerger::union($old->rules, $new->rules) ?? [],
			$new->flag,
			$new->sessionTokenId,
			CommonFacts::merge($old->common, $new->common),
		);
	}

	#[\Override]
	public function mergedOnto(array $stored): array {
		return array_replace($stored, self::merge(self::fromArray($stored), $this)->toArray());
	}
}
