<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\ShareBruteforce;

use OCA\IntrusionDetection\Detection\CommonFacts;
use OCA\IntrusionDetection\Detection\FactsMerger;
use OCA\IntrusionDetection\Detection\FactValues;
use OCA\IntrusionDetection\Detection\IMergeableFacts;

/**
 * What a share link attack detection recorded: unknown share links tried
 * by an address or a network, or wrong passwords for one share. Identifies
 * the share by its id and the accounts that manage it, never by its token
 * or name. Counts of links are estimates when attempts were sampled.
 */
final readonly class ShareBruteforceFacts implements IMergeableFacts {
	/**
	 * @param ?int $tokens the different unknown links tried
	 * @param ?int $attempts the attempts with unknown links
	 * @param ?int $failures the wrong passwords for the share
	 * @param ?int $sources the addresses they came from
	 * @param ?int $sampleFactor one in this many attempts was recorded
	 * @param ?string $lastSource the address of the most recent wrong password
	 * @param ?string $net the IPv4 /24 of a network detection
	 * @param ?bool $loggedIn the most recent link was opened while logged in
	 * @param ?bool $federation the address belongs to a federation partner
	 * @param ?int $partners the addresses of the network that belong to federation partners
	 * @param ?string $owner the first account that manages the share, null when none does; recorded with the share
	 * @param ?list<string> $managers the accounts that manage the share
	 * @param ?string $share its full id, such as "ocinternal:42"
	 * @param ?int $shareType its share type
	 */
	public function __construct(
		public ?ShareBruteforceRule $rule = null,
		public ?int $tokens = null,
		public ?int $attempts = null,
		public ?int $failures = null,
		public ?int $sources = null,
		public ?int $sampleFactor = null,
		public ?string $lastSource = null,
		public ?string $net = null,
		public ?bool $loggedIn = null,
		public ?bool $federation = null,
		public ?int $partners = null,
		public ?string $owner = null,
		public ?array $managers = null,
		public ?string $share = null,
		public ?int $shareType = null,
		public CommonFacts $common = new CommonFacts(),
	) {
	}

	/**
	 * @param array<array-key, mixed> $stored
	 */
	public static function fromArray(array $stored): self {
		return new self(
			ShareBruteforceRule::tryFrom((string)FactValues::string($stored, 'rule')),
			FactValues::int($stored, 'tokens'),
			FactValues::int($stored, 'attempts'),
			FactValues::int($stored, 'failures'),
			FactValues::int($stored, 'sources'),
			FactValues::int($stored, 'sampleFactor'),
			FactValues::string($stored, 'lastSource'),
			FactValues::string($stored, 'net'),
			FactValues::bool($stored, 'loggedIn'),
			FactValues::bool($stored, 'federation'),
			FactValues::int($stored, 'partners'),
			FactValues::string($stored, 'owner'),
			FactValues::strings($stored, 'managers'),
			FactValues::string($stored, 'share'),
			FactValues::int($stored, 'shareType'),
			CommonFacts::fromArray($stored),
		);
	}

	#[\Override]
	public function toArray(): array {
		$facts = FactValues::recorded([
			'rule' => $this->rule?->value,
			'tokens' => $this->tokens,
			'attempts' => $this->attempts,
			'failures' => $this->failures,
			'sources' => $this->sources,
			'sampleFactor' => $this->sampleFactor,
			'lastSource' => $this->lastSource,
			'net' => $this->net,
			'loggedIn' => $this->loggedIn,
			'federation' => $this->federation,
			'partners' => $this->partners,
			'managers' => $this->managers,
			'share' => $this->share,
			'shareType' => $this->shareType,
		]);
		if ($this->share !== null) {
			// Recorded with the share even when no account manages it.
			$facts['owner'] = $this->owner;
		}
		return $facts + $this->common->toArray();
	}

	/**
	 * The rule stays, the accounts that manage the share are those of every
	 * hit, the rest is the latest.
	 */
	public static function merge(self $old, self $new): self {
		return new self(
			$old->rule ?? $new->rule,
			$new->tokens ?? $old->tokens,
			$new->attempts ?? $old->attempts,
			$new->failures ?? $old->failures,
			$new->sources ?? $old->sources,
			$new->sampleFactor ?? $old->sampleFactor,
			$new->lastSource ?? $old->lastSource,
			$new->net ?? $old->net,
			$new->loggedIn ?? $old->loggedIn,
			$new->federation ?? $old->federation,
			$new->partners ?? $old->partners,
			$new->share !== null ? $new->owner : $old->owner,
			FactsMerger::union($old->managers, $new->managers),
			$new->share ?? $old->share,
			$new->shareType ?? $old->shareType,
			CommonFacts::merge($old->common, $new->common),
		);
	}

	#[\Override]
	public function mergedOnto(array $stored): array {
		return array_replace($stored, self::merge(self::fromArray($stored), $this)->toArray());
	}
}
