<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Admin;

use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Definition\Category;
use OCP\IL10N;

/**
 * The display name and category of a check id, for lists of detections and
 * blocks. A check that no longer exists is shown by its id.
 */
class CheckNames {
	/** @var array<string, string> */
	private array $names = [];
	/** @var array<string, string> */
	private array $shortNames = [];

	public function __construct(
		private readonly CheckRegistry $registry,
	) {
	}

	public function name(string $checkId, IL10N $l): string {
		$key = $l->getLanguageCode() . "\0" . $checkId;
		return $this->names[$key] ??= $this->registry->has($checkId) ? $this->registry->get($checkId)->texts($l)->name : $checkId;
	}

	/**
	 * A name of a few words, for places with little room; the full name when
	 * a check has no short one.
	 */
	public function shortName(string $checkId, IL10N $l): string {
		$key = $l->getLanguageCode() . "\0" . $checkId;
		if (!isset($this->shortNames[$key])) {
			$short = $this->registry->has($checkId) ? $this->registry->get($checkId)->texts($l)->shortName : '';
			$this->shortNames[$key] = $short !== '' ? $short : $this->name($checkId, $l);
		}
		return $this->shortNames[$key];
	}

	/**
	 * What the check detects, in one plain sentence; empty for a check that
	 * no longer exists.
	 */
	public function summary(string $checkId, IL10N $l): string {
		return $this->registry->has($checkId) ? $this->registry->get($checkId)->texts($l)->summary : '';
	}

	public function category(string $checkId): Category {
		return $this->registry->has($checkId) ? $this->registry->get($checkId)->category : Category::Internal;
	}
}
