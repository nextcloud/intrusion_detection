<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Event;

use OCP\EventDispatcher\Event;

/**
 * A setting of the app was changed through {@see \OCA\IntrusionDetection\Config\Settings},
 * the only place that writes them. Internal state is not reported.
 *
 * The values are the effective ones before and after the change (defaults
 * included), as the settings service reads them.
 *
 * A change that is not reported ({@see self::isReported()}) was made by the
 * app on its own, or by a feature that writes it to the audit log itself:
 * it is no administration change.
 */
class SettingChangedEvent extends Event {
	/**
	 * @param int|float|bool|string|list<string> $oldValue
	 * @param int|float|bool|string|list<string> $newValue
	 */
	public function __construct(
		private readonly string $key,
		private readonly int|float|bool|string|array $oldValue,
		private readonly int|float|bool|string|array $newValue,
		private readonly bool $reported = true,
	) {
		parent::__construct();
	}

	public function getKey(): string {
		return $this->key;
	}

	/**
	 * @return int|float|bool|string|list<string>
	 */
	public function getOldValue(): int|float|bool|string|array {
		return $this->oldValue;
	}

	/**
	 * @return int|float|bool|string|list<string>
	 */
	public function getNewValue(): int|float|bool|string|array {
		return $this->newValue;
	}

	/**
	 * Whether the change is reported as an administration change.
	 */
	public function isReported(): bool {
		return $this->reported;
	}
}
