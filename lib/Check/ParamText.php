<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check;

/**
 * How the admin page labels one parameter: a short label, an optional help
 * sentence, and the unit shown next to the field (for example "failures").
 * Durations need no unit: the page offers seconds to days.
 */
final class ParamText {
	public function __construct(
		public readonly string $label,
		public readonly string $help = '',
		public readonly string $unit = '',
	) {
	}
}
