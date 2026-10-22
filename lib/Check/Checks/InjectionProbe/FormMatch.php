<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\InjectionProbe;

/**
 * The signatures that matched one form of a value: the value itself, or the
 * text decoded from it once or twice.
 */
final class FormMatch {
	public const ENCODING_NONE = 'none';
	public const ENCODING_BASE64 = 'base64';
	public const ENCODING_BASE64_TWICE = 'base64_twice';

	/**
	 * @param self::ENCODING_* $encoding
	 * @param string $text the normalised text the signatures ran on
	 * @param array<string, int> $matches signature id => weight
	 * @param int $offset byte offset of the first match in `$text`, -1 when nothing matched
	 */
	public function __construct(
		public readonly string $encoding,
		public readonly string $text,
		public readonly array $matches,
		public readonly int $weight,
		public readonly int $offset,
	) {
	}

	/**
	 * @param int<0, max> $level number of base64 decodings before the text
	 * @return self::ENCODING_*
	 */
	public static function encodingFor(int $level): string {
		return match ($level) {
			0 => self::ENCODING_NONE,
			1 => self::ENCODING_BASE64,
			default => self::ENCODING_BASE64_TWICE,
		};
	}
}
