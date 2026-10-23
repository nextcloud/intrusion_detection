<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\WasThisYou;

use OCP\IL10N;

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
	 * @param bool $yes whether the refused answer was "Yes, it was me"
	 */
	public function __construct(
		public readonly string $reason,
		public readonly bool $yes = false,
	) {
		parent::__construct($reason);
	}

	public function describe(IL10N $l): string {
		return match ($this->reason) {
			self::NOT_FOUND => $l->t('This event does not exist, or it is not about your account.'),
			self::NOT_ASKED => $l->t('This event does not need an answer.'),
			self::ANSWERED => $l->t('This event was answered already.'),
			default => $this->yes
				? $l->t('For your safety, "Yes, it was me" can only be answered in a browser, after a login with your second factor or an email code, or from a device you remembered. It cannot be answered from the session this event is about.')
				: $l->t('For your safety, "No, it was not me" cannot be answered from a login that was not confirmed. Answer from another device, or after a login with your second factor or an email code.'),
		};
	}
}
