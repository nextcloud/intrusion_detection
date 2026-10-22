<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks;

use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCA\IntrusionDetection\Traps\ReservedNames;

/**
 * Detects failed logins with a reserved name (concept section 10.7).
 * Repeated attempts from one address within an hour are one detection.
 */
class ReservedNameDetector {
	public function __construct(
		private readonly CheckSettings $settings,
		private readonly ReservedNames $names,
		private readonly ResponseEngine $engine,
	) {
	}

	/**
	 * @return bool whether the login name was a reserved name
	 */
	public function detect(SourceKey $source, string $loginName, ?string $userAgent): bool {
		if (!$this->settings->modeState(ReservedName::ID)->runs()) {
			return false;
		}
		$name = $this->names->match($loginName);
		if ($name === null) {
			return false;
		}
		$this->engine->handle(new DetectionDraft(
			checkId: ReservedName::ID,
			source: $source,
			facts: ['name' => $name],
			merge: DetectionDraft::MERGE_SOURCE,
			userAgent: $userAgent,
		));
		return true;
	}
}
