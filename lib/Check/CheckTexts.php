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
 * (on the admin page, while typing). `cost` adds to the cost class text what
 * this check costs in particular (for an external call: what, how often, how
 * long), with the same placeholders.
 */
final class CheckTexts {
	/**
	 * @param array<string, ParamText> $params label, help and unit per parameter name
	 */
	public function __construct(
		public readonly string $name,
		public readonly string $summary,
		public readonly string $detects,
		public readonly string $decides,
		public readonly string $wrong,
		public readonly string $data,
		public readonly array $params = [],
		public readonly string $cost = '',
	) {
	}

	/**
	 * The texts of one parameter; a parameter without texts is labelled by its name.
	 */
	public function param(string $name): ParamText {
		return $this->params[$name] ?? new ParamText(ucfirst(str_replace('_', ' ', $name)));
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
