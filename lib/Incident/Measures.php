<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Incident;

use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCP\IL10N;

/**
 * What was really done about a detection, for the summary of an incident
 * report: the enforced actions that ran, told like in the narrative, without
 * what was unavailable, failed or not needed, and nothing for detections
 * that were only observed.
 */
class Measures {
	public function __construct(
		private readonly NarrativeBuilder $narratives,
	) {
	}

	/**
	 * @return list<string>
	 */
	public function of(Detection $detection, IL10N $l): array {
		$ran = array_values(array_filter($detection->getActionList(), static fn (array $action): bool => $action['enforced'] && !isset($action['note'])));
		if (!$detection->isEnforced() || $ran === []) {
			return [];
		}
		// A copy, so the stored detection stays as it is.
		$copy = clone $detection;
		$copy->setActionList($ran);
		return $this->narratives->build($copy, $l)->done;
	}
}
