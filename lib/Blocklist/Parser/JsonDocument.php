<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Blocklist\Parser;

/**
 * Helpers for the providers' JSON range documents.
 */
final class JsonDocument {
	/**
	 * @return array<array-key, mixed>
	 * @throws ListFormatException
	 */
	public static function decode(string $body): array {
		try {
			$data = json_decode($body, true, 16, JSON_THROW_ON_ERROR);
		} catch (\JsonException) {
			throw new ListFormatException('Not JSON');
		}
		if (!is_array($data)) {
			throw new ListFormatException('Not a JSON object');
		}
		return $data;
	}

	/**
	 * Add the `$field` of every object in a list of objects.
	 */
	public static function collect(ParsedList $list, mixed $objects, string $field): void {
		if (!is_array($objects)) {
			return;
		}
		foreach ($objects as $object) {
			$value = is_array($object) ? ($object[$field] ?? null) : null;
			$list->add(is_string($value) ? $value : '');
		}
	}
}
