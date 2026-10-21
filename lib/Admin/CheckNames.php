<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Admin;

use OCA\IntrusionDetection\Check\Category;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCP\IL10N;

/**
 * The display name and category of a check id, for lists of detections and
 * blocks. A check that no longer exists is shown by its id.
 */
class CheckNames {
	/** @var array<string, string> */
	private array $names = [];

	public function __construct(
		private readonly CheckRegistry $registry,
	) {
	}

	public function name(string $checkId, IL10N $l): string {
		$key = $l->getLanguageCode() . "\0" . $checkId;
		return $this->names[$key] ??= $this->registry->has($checkId) ? $this->registry->get($checkId)->texts($l)->name : $checkId;
	}

	public function category(string $checkId): Category {
		return $this->registry->has($checkId) ? $this->registry->get($checkId)->category : Category::Internal;
	}
}
