<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\BreachedPassword;

use OCA\IntrusionDetection\Detection\CommonFacts;
use OCA\IntrusionDetection\Detection\FactValues;
use OCA\IntrusionDetection\Detection\IMergeableFacts;

/**
 * What a breached password detection recorded. The count of the password
 * in the list is never stored: it could identify the password.
 */
final readonly class BreachedPasswordFacts implements IMergeableFacts {
	/** The password was checked at an interactive login */
	public const TRIGGER_LOGIN = 'login';

	/**
	 * @param string $trigger when the password was checked, {@see self::TRIGGER_LOGIN}
	 */
	public function __construct(
		public string $trigger = '',
		public CommonFacts $common = new CommonFacts(),
	) {
	}

	/**
	 * @param array<array-key, mixed> $stored
	 */
	public static function fromArray(array $stored): self {
		return new self(
			FactValues::string($stored, 'trigger') ?? '',
			CommonFacts::fromArray($stored),
		);
	}

	#[\Override]
	public function toArray(): array {
		return [
			'trigger' => $this->trigger,
		] + $this->common->toArray();
	}

	/**
	 * The trigger is the latest.
	 */
	public static function merge(self $old, self $new): self {
		return new self(
			$new->trigger,
			CommonFacts::merge($old->common, $new->common),
		);
	}

	#[\Override]
	public function mergedOnto(array $stored): array {
		return array_replace($stored, self::merge(self::fromArray($stored), $this)->toArray());
	}
}
