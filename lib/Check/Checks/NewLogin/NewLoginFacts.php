<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\NewLogin;

use OCA\IntrusionDetection\Detection\CommonFacts;
use OCA\IntrusionDetection\Detection\FactValues;
use OCA\IntrusionDetection\Detection\IMergeableFacts;

/**
 * What a login from a new device on a new network recorded: the kind of
 * device, as {@see \OCA\IntrusionDetection\KnownDevice\DeviceLabel} names
 * it, and whether the password was typed.
 */
final readonly class NewLoginFacts implements IMergeableFacts {
	/**
	 * @param string $family the browser, as {@see \OCA\IntrusionDetection\KnownDevice\DeviceLabel::parse()} gives it
	 * @param string $platform the system, likewise
	 * @param bool $typedPassword the login typed the account's password
	 */
	public function __construct(
		public string $family = 'other',
		public string $platform = 'other',
		public bool $typedPassword = false,
		public CommonFacts $common = new CommonFacts(),
	) {
	}

	/**
	 * @param array<array-key, mixed> $stored
	 */
	public static function fromArray(array $stored): self {
		return new self(
			FactValues::string($stored, 'family') ?? 'other',
			FactValues::string($stored, 'platform') ?? 'other',
			FactValues::bool($stored, 'typedPassword') ?? false,
			CommonFacts::fromArray($stored),
		);
	}

	#[\Override]
	public function toArray(): array {
		return [
			'family' => $this->family,
			'platform' => $this->platform,
			'typedPassword' => $this->typedPassword,
		] + $this->common->toArray();
	}

	#[\Override]
	public function mergedOnto(array $stored): array {
		$old = self::fromArray($stored);
		return array_replace($stored, (new self(
			$this->family,
			$this->platform,
			$old->typedPassword || $this->typedPassword,
			CommonFacts::merge($old->common, $this->common),
		))->toArray());
	}
}
