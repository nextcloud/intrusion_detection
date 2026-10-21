<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Admin;

use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\IL10N;

/**
 * A check's name and mode, for panels that depend on a check without
 * showing its card, such as the blocklists (which act through
 * `blocklist_match`) or the decoys.
 *
 * @psalm-import-type IntrusionDetectionModeState from ResponseDefinitions
 */
class CheckSummary {
	public function __construct(
		private readonly CheckRegistry $registry,
		private readonly Settings $settings,
	) {
	}

	/**
	 * @return array{id: string, name: string, mode: IntrusionDetectionModeState}
	 */
	public function of(string $id, IL10N $l): array {
		$check = $this->registry->get($id);
		$state = $this->settings->modeState($id);
		return [
			'id' => $id,
			'name' => $check->texts($l)->name,
			'mode' => [
				'configured' => $state->configured->value,
				'effective' => $state->effective->value,
				'reason' => $state->reason,
				'missing' => $state->missing?->value,
				'default' => $check->defaultMode->value,
			],
		];
	}
}
