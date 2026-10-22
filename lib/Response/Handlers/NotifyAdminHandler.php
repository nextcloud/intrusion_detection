<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Response\Handlers;

use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Explain\IDescribesAction;
use OCA\IntrusionDetection\Notification\AdminAlerts;
use OCA\IntrusionDetection\Response\IResponseHandler;
use OCA\IntrusionDetection\Response\ResponseContext;
use OCA\IntrusionDetection\Response\ResponseOutcome;
use OCP\IL10N;

/**
 * Notifies the administrators, aggregated per check, source and hour; see
 * {@see AdminAlerts}. A merged hit only raises the counter of the
 * notification sent for the first one.
 */
class NotifyAdminHandler implements IResponseHandler, IDescribesAction {
	public function __construct(
		private readonly AdminAlerts $alerts,
	) {
	}

	#[\Override]
	public function type(): ResponseType {
		return ResponseType::NotifyAdmin;
	}

	#[\Override]
	public function apply(ResponseContext $context): ResponseOutcome {
		$result = $this->alerts->alert($context->detection);
		if ($result['recipients'] === 0) {
			return ResponseOutcome::skipped(ResponseOutcome::NOTE_NOTHING_TO_DO, $result);
		}
		return ResponseOutcome::done($result);
	}

	#[\Override]
	public function describeAction(array $action, IL10N $l, DateFormatter $dates): array {
		$ref = is_array($action['ref'] ?? null) ? $action['ref'] : [];
		$recipients = (int)($ref['recipients'] ?? 0);
		$sentences = [$l->n('%n administrator was notified.', '%n administrators were notified.', $recipients)];
		$sentences[] = match ($ref['email'] ?? null) {
			AdminAlerts::EMAIL_SENT => $l->t('An email was sent as well.'),
			AdminAlerts::EMAIL_QUEUED => $l->t('An email was queued as well.'),
			AdminAlerts::EMAIL_LIMITED => $l->t('No email was sent, because one was already sent for this check within the hour.'),
			AdminAlerts::EMAIL_NO_ADDRESS => $l->t('No email was sent, because no administrator has an email address. They only see the notification inside Nextcloud.'),
			AdminAlerts::EMAIL_FAILED => $l->t('The email could not be sent. Check the email settings; the administrators only see the notification inside Nextcloud.'),
			default => $l->t('No email was sent: emails are only sent for more severe detections.'),
		};
		return $sentences;
	}
}
