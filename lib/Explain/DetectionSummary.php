<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Explain;

use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCP\IL10N;

/**
 * One plain sentence about a detection, the first thing the admin page
 * shows of it: what happened ({@see DetectionHeadline}) and the most
 * important thing Nextcloud did about it, e.g. "Credential stuffing from
 * 203.0.113.7. The address was blocked." The full narrative stays in the
 * detail.
 */
class DetectionSummary {
	public function __construct(
		private readonly DetectionHeadline $headlines,
	) {
	}

	public function summary(Detection $detection, IL10N $l): string {
		// TRANSLATORS: what happened, then what Nextcloud did, e.g. "Credential stuffing from 203.0.113.7. The address was blocked."
		return $l->t('%1$s. %2$s', [$this->headlines->headline($detection, $l), $this->outcome($detection, $l)]);
	}

	/**
	 * The first response that really acted, in the order the responses run
	 * (blocks first, notifications last); an observed detection says why
	 * nothing was done.
	 */
	public function outcome(Detection $detection, IL10N $l): string {
		if (!$detection->isEnforced()) {
			$reason = $detection->getExplanationData()['mode']['reason'] ?? null;
			return match ($reason) {
				ModeState::REASON_LEARNING => $l->t('Only recorded, as learning mode was on.'),
				ModeState::REASON_AUTHENTICATED => $l->t('Only recorded, as it came from a logged-in user.'),
				default => $l->t('Only recorded, as the check observes.'),
			};
		}
		$done = [];
		foreach ($detection->getActionList() as $action) {
			$type = ResponseType::tryFrom((string)$action['type']);
			$note = $action['note'] ?? null;
			if ($type !== null && $action['enforced'] && $note === null) {
				$done[] = $type;
			}
		}
		usort($done, static fn (ResponseType $a, ResponseType $b): int => $a->order() <=> $b->order());
		return $done === [] ? $l->t('It was recorded.') : self::done($done[0], $l);
	}

	private static function done(ResponseType $type, IL10N $l): string {
		return match ($type) {
			ResponseType::Ban => $l->t('The address was blocked.'),
			ResponseType::RevokeToken => $l->t('The app password or token was revoked.'),
			ResponseType::KillSession => $l->t('The session was ended.'),
			ResponseType::ForcePasswordChange => $l->t('A new password is required at the next login.'),
			ResponseType::ProtectAccount => $l->t('Logins to the account need extra confirmation for a while.'),
			ResponseType::FlagSource => $l->t('Logins from the address need extra confirmation.'),
			ResponseType::FlagPassword => $l->t('Logins with the guessed password need extra confirmation.'),
			ResponseType::SuppressResetMail => $l->t('Password reset emails to the account are paused.'),
			ResponseType::RateLimit => $l->t('Further requests were refused for a few minutes.'),
			ResponseType::StepUp => $l->t('The login had to be confirmed.'),
			ResponseType::LockLink => $l->t('The previous email address got a link to lock the account.'),
			ResponseType::NotifyAdmin => $l->t('The administrators were notified.'),
			ResponseType::NotifyUser => $l->t('The user was told.'),
			ResponseType::NotifyShareOwner => $l->t('The owner of the share was told.'),
		};
	}
}
