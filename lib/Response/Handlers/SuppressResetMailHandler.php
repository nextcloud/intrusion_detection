<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Response\Handlers;

use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Config\Settings;
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
 * suppression, so that it ends that long after the last request.
 */
class SuppressResetMailHandler implements IResponseHandler, IDescribesAction {
	/** Used for checks without a `suppress_duration` parameter */
	public const DEFAULT_DURATION = 3600;

	public function __construct(
		private readonly ResetMailSuppressor $suppressor,
		private readonly Settings $settings,
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
		$until = $this->suppressor->suppress($uid, $this->timeFactory->getTime() + $duration, $context->detection->getId());
		return ResponseOutcome::done(['uid' => $uid, 'until' => $until]);
	}

	#[\Override]
	public function describeAction(array $action, IL10N $l, DateFormatter $dates): array {
		$ref = is_array($action['ref'] ?? null) ? $action['ref'] : [];
		$until = (int)($ref['until'] ?? 0);
		$uid = (string)($ref['uid'] ?? '');
		return [$until > 0
			? $l->t('Until %1$s, no password reset emails are sent to %2$s. Whoever asks for one gets the usual answer.', [$dates->dateTime($until), $uid])
			: $l->t('For a while, no password reset emails are sent to this account.')];
	}
}
