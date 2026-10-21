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
use OCA\IntrusionDetection\Notification\UserAlerts;
use OCA\IntrusionDetection\Response\IResponseHandler;
use OCA\IntrusionDetection\Response\ResponseContext;
use OCA\IntrusionDetection\Response\ResponseOutcome;
use OCP\IL10N;

/**
 * Tells the detection's account holder, aggregated; see {@see UserAlerts}.
 * It runs last, so the user is told what Nextcloud did.
 */
class NotifyUserHandler implements IResponseHandler, IDescribesAction {
	public function __construct(
		private readonly UserAlerts $alerts,
	) {
	}

	#[\Override]
	public function type(): ResponseType {
		return ResponseType::NotifyUser;
	}

	#[\Override]
	public function apply(ResponseContext $context): ResponseOutcome {
		$result = $this->alerts->notify($context->detection, $context->isNew);
		if ($result === null) {
			return ResponseOutcome::skipped(ResponseOutcome::NOTE_NOTHING_TO_DO);
		}
		if ($result['bell'] === UserAlerts::BELL_AGGREGATED) {
			// Told already for an earlier hit: keep what that one recorded.
			return ResponseOutcome::skipped(ResponseOutcome::NOTE_NOTHING_TO_DO, $result);
		}
		return ResponseOutcome::done($result);
	}

	#[\Override]
	public function describeAction(array $action, IL10N $l, DateFormatter $dates): array {
		$ref = is_array($action['ref'] ?? null) ? $action['ref'] : [];
		$sentences = [match ($ref['email'] ?? null) {
			UserAlerts::EMAIL_SENT => $l->t('The user was told with a notification and an email.'),
			UserAlerts::EMAIL_NO_ADDRESS => $l->t('The user was told with a notification only: they have no email address.'),
			UserAlerts::EMAIL_FAILED => $l->t('The user was told with a notification; the email could not be sent.'),
			default => $l->t('The user was told with a notification.'),
		}];
		$admins = (int)($ref['admins'] ?? 0);
		if ($admins > 0) {
			$sentences[] = $l->n(
				'%n administrator was told that the user could only be reached inside Nextcloud.',
				'%n administrators were told that the user could only be reached inside Nextcloud.',
				$admins,
			);
		}
		return $sentences;
	}
}
