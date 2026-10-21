<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Payload;

/**
 * One part of a request: the path, a query parameter or a form field, with
 * the raw value to inspect, or the reason it is not inspected.
 */
final class InspectedValue {
	public const SKIPPED_BUDGET = 'budget';

	/**
	 * @param PayloadHit::LOCATION_* $location
	 * @param string $name decoded parameter name, safe to show ('' for the path)
	 * @param ?string $raw the value as sent, cut to the byte budget; null when it is not inspected
	 * @param PayloadRules::EXCLUDED_*|self::SKIPPED_BUDGET|null $skipped why the value is not inspected
	 */
	public function __construct(
		public readonly string $location,
		public readonly string $name,
		public readonly ?string $raw,
		public readonly ?string $skipped = null,
		public readonly bool $truncated = false,
	) {
	}
}
