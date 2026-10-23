<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Response\Handlers;

use OCA\IntrusionDetection\Confirm\StepUpReasons;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Explain\IDescribesAction;
use OCA\IntrusionDetection\Response\IResponseHandler;
use OCA\IntrusionDetection\Response\ResponseContext;
use OCA\IntrusionDetection\Response\ResponseOutcome;
use OCP\IL10N;

/**
 * Records that the account's password logins need extra confirmation
 * because of this detection. The confirmation itself is asked at login: the
 * step-up reasons ({@see StepUpReasons}) look at the check's mode and at
 * whether this response is selected, so that switching it off here also
 * stops the confirmation.
 */
class StepUpHandler implements IResponseHandler, IDescribesAction {
	#[\Override]
	public function type(): ResponseType {
		return ResponseType::StepUp;
	}

	#[\Override]
	public function apply(ResponseContext $context): ResponseOutcome {
		if ($context->draft->uid === null) {
			return ResponseOutcome::skipped(ResponseOutcome::NOTE_NOTHING_TO_DO);
		}
		return ResponseOutcome::done();
	}

	#[\Override]
	public function describeAction(array $action, IL10N $l, DateFormatter $dates): array {
		return [$l->t('Password logins of the account need extra confirmation: the second factor, or a code sent by email.')];
	}
}
