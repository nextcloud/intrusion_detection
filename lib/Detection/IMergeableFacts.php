<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Detection;

/**
 * The facts of a check whose repeated hits join one detection
 * ({@see DetectionDraft::$merge}). The class declares how each fact
 * merges, in its static `merge()`.
 */
interface IMergeableFacts extends IFacts {
	/**
	 * The stored facts of the detection a repeated hit joins, with the
	 * facts of this hit merged in. Stored facts the class does not know
	 * stay as they are.
	 *
	 * @param array<array-key, mixed> $stored
	 * @return array<array-key, mixed>
	 */
	public function mergedOnto(array $stored): array;
}
