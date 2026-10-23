<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\InjectionProbe;

/**
 * One signature: a regular expression run on a normalised value, and the
 * weight it adds when it matches.
 */
final class Signature {
	/** Runs on plain values and on decoded base64 */
	public const SCOPE_ANY = 'any';
	/** Runs only on text decoded from base64 */
	public const SCOPE_ENCODED = 'encoded';

	/**
	 * @param string $pattern a complete PCRE pattern with delimiters, run on lower-cased text
	 * @param self::SCOPE_* $scope
	 * @param bool $requiresOther counts only when another signature matched the same text
	 */
	public function __construct(
		public readonly string $id,
		public readonly string $pattern,
		public readonly int $weight,
		public readonly string $scope = self::SCOPE_ANY,
		public readonly bool $requiresOther = false,
		public readonly bool $custom = false,
	) {
	}

	public function appliesTo(bool $decoded): bool {
		return $decoded || $this->scope === self::SCOPE_ANY;
	}
}
