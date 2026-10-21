<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\AdminChange;

/**
 * The current value of one watched setting.
 *
 * `fixed` settings are always watched, set or not, so a missing snapshot row
 * means the watch list grew (it is recorded silently). Other settings are
 * found by a prefix or by listing an app's keys; for them a missing row means
 * the setting was not set before.
 */
final class WatchedValue {
	public function __construct(
		public readonly string $key,
		/** null when the setting is not set */
		#[\SensitiveParameter]
		public readonly mixed $value,
		public readonly bool $secret,
		public readonly bool $fixed,
		/** The text to compare instead of the value's, for settings whose stored value differs from the shown one */
		#[\SensitiveParameter]
		private readonly ?string $compared = null,
	) {
	}

	/**
	 * The canonical text the keyed hash is computed over.
	 */
	public function canonical(): string {
		return $this->compared ?? self::canonicalOf($this->value);
	}

	public static function canonicalOf(#[\SensitiveParameter] mixed $value): string {
		// serialize() is exact for scalars and arrays, also for text that is not valid UTF-8.
		return serialize($value);
	}

	/**
	 * The stored display value: null for secrets, else the shortened value as JSON.
	 */
	public function display(): ?string {
		return $this->secret ? null : DisplayValue::encode($this->value);
	}
}
