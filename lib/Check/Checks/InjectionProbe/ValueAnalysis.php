<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\InjectionProbe;

/**
 * Everything the matcher found out about one value.
 */
final class ValueAnalysis {
	/**
	 * @param list<string> $decoded the text decoded from base64, one entry per level (for paths: per segment and level)
	 * @param list<FormMatch> $forms the plain form first, then the decoded ones
	 */
	public function __construct(
		public readonly array $decoded,
		public readonly array $forms,
		public readonly int $minWeight,
	) {
	}

	/**
	 * The form with the highest total weight; the plain form when nothing matched.
	 */
	public function strongest(): FormMatch {
		$best = $this->forms[0];
		foreach ($this->forms as $form) {
			if ($form->weight > $best->weight) {
				$best = $form;
			}
		}
		return $best;
	}

	public function fires(): bool {
		return $this->strongest()->weight >= $this->minWeight;
	}

	public function normalised(): string {
		return $this->forms[0]->text;
	}
}
