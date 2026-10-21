<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\WasThisYou;

/**
 * Why an answer to "Was this you?" was not taken.
 */
class AnswerException extends \Exception {
	/** No such detection of this account (also for other accounts' detections) */
	public const NOT_FOUND = 'not_found';
	/** The detection does not ask */
	public const NOT_ASKED = 'not_asked';
	/** It was answered already */
	public const ANSWERED = 'answered';
	/** "Yes" from the session the detection is about, or from a session that is not trusted to vouch */
	public const SESSION_NOT_ALLOWED = 'session_not_allowed';

	/**
	 * @param self::* $reason
	 */
	public function __construct(
		public readonly string $reason,
	) {
		parent::__construct($reason);
	}
}
