<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check;

/**
 * The translated texts that explain a check.
 *
 * `decides` is a template: `{param}` placeholders are filled with the current
 * value of that parameter, so the sentence follows the settings as they change
 * (on the admin page, while typing).
 */
final class CheckTexts {
	public function __construct(
		public readonly string $name,
		public readonly string $summary,
		public readonly string $detects,
		public readonly string $decides,
		public readonly string $wrong,
		public readonly string $data,
	) {
	}

	/**
	 * @return array{name: string, summary: string, detects: string, decides: string, wrong: string, data: string}
	 */
	public function toArray(): array {
		return [
			'name' => $this->name,
			'summary' => $this->summary,
			'detects' => $this->detects,
			'decides' => $this->decides,
			'wrong' => $this->wrong,
			'data' => $this->data,
		];
	}
}
