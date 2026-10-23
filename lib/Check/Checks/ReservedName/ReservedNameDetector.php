<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\ReservedName;

use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Signal\FailedLogin;
use OCA\IntrusionDetection\Signal\IDetector;
use OCA\IntrusionDetection\Signal\ISignal;
use OCA\IntrusionDetection\Traps\ReservedNames;

/**
 * Detects failed logins with a reserved name (concept section 10.7).
 * Repeated attempts from one address within an hour are one detection.
 * A reserved name answers the failed login on its own: it is not counted
 * as an attempt.
 *
 * @template-implements IDetector<FailedLogin>
 */
class ReservedNameDetector implements IDetector {
	public function __construct(
		private readonly ReservedNames $names,
	) {
	}

	/**
	 * @param FailedLogin $signal
	 * @return list<DetectionDraft>
	 */
	#[\Override]
	public function detect(#[\SensitiveParameter] ISignal $signal, ModeState $mode): iterable {
		$name = $this->names->match($signal->loginName);
		if ($name === null) {
			return [];
		}
		return [new DetectionDraft(
			checkId: ReservedName::ID,
			source: $signal->source,
			facts: ['name' => $name],
			merge: DetectionDraft::MERGE_SOURCE,
			userAgent: $signal->userAgent,
			final: true,
		)];
	}
}
