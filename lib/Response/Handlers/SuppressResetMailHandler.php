<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Response\Handlers;

use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Explain\IDescribesAction;
use OCA\IntrusionDetection\Response\IResponseHandler;
use OCA\IntrusionDetection\Response\ResetMailSuppressor;
use OCA\IntrusionDetection\Response\ResponseContext;
use OCA\IntrusionDetection\Response\ResponseOutcome;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IL10N;

/**
 * Stops sending password reset emails to the detection's account for the
 * check's `suppress_duration` (an hour by default), or extends a running
 * suppression, so that it ends that long after the last request; never for
 * longer than {@see ResetMailSuppressor::MAX_SUPPRESSION} in a row.
 */
class SuppressResetMailHandler implements IResponseHandler, IDescribesAction {
	/** Used for checks without a `suppress_duration` parameter */
	public const DEFAULT_DURATION = 3600;

	public function __construct(
		private readonly ResetMailSuppressor $suppressor,
		private readonly CheckSettings $settings,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	#[\Override]
	public function type(): ResponseType {
		return ResponseType::SuppressResetMail;
	}

	#[\Override]
	public function apply(ResponseContext $context): ResponseOutcome {
		$uid = $context->draft->uid;
		if ($uid === null) {
			return ResponseOutcome::skipped(ResponseOutcome::NOTE_NOTHING_TO_DO);
		}
		$duration = $context->definition->hasParam('suppress_duration')
			? $this->settings->paramInt($context->definition->id, 'suppress_duration')
			: self::DEFAULT_DURATION;
		$now = $this->timeFactory->getTime();
		['until' => $until, 'latest' => $latest] = $this->suppressor->suppress($uid, $now + $duration, $context->detection->getId());
		$ref = ['uid' => $uid, 'until' => $until, 'latest' => $latest];
		return $until > $now ? ResponseOutcome::done($ref) : ResponseOutcome::skipped(ResponseOutcome::NOTE_HELD_BACK, $ref);
	}

	#[\Override]
	public function describeAction(array $action, IL10N $l, DateFormatter $dates): array {
		$ref = is_array($action['ref'] ?? null) ? $action['ref'] : [];
		$until = (int)($ref['until'] ?? 0);
		$latest = (int)($ref['latest'] ?? 0);
		$uid = (string)($ref['uid'] ?? '');
		if (!$action['enforced'] && $latest > 0) {
			return [$l->t('Password reset emails to %1$s are sent again: they were already held back for as long as allowed, until %2$s at the latest. Nextcloud holds them back for at most a day within two days, so that nobody can keep a person from resetting their password.', [$uid, $dates->dateTime($latest)])];
		}
		return [$until > 0
			? $l->t('Until %1$s, no password reset emails are sent to %2$s. Whoever asks for one gets the usual answer.', [$dates->dateTime($until), $uid])
			: $l->t('For a while, no password reset emails are sent to this account.')];
	}
}
