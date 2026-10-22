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
use OCA\IntrusionDetection\Notification\ShareOwnerAlerts;
use OCA\IntrusionDetection\Response\IResponseHandler;
use OCA\IntrusionDetection\Response\ResponseContext;
use OCA\IntrusionDetection\Response\ResponseOutcome;
use OCA\IntrusionDetection\Share\ShareLinks;
use OCP\IL10N;

/**
 * Tells the people who manage the detection's share (bell and email), once
 * per detection: further wrong passwords merge into it, and the
 * notification shows the current count.
 */
class NotifyShareOwnerHandler implements IResponseHandler, IDescribesAction {
	public function __construct(
		private readonly ShareLinks $links,
		private readonly ShareOwnerAlerts $alerts,
	) {
	}

	#[\Override]
	public function type(): ResponseType {
		return ResponseType::NotifyShareOwner;
	}

	#[\Override]
	public function apply(ResponseContext $context): ResponseOutcome {
		if (!$context->isNew || $context->detection->getShareId() === null) {
			return ResponseOutcome::skipped(ResponseOutcome::NOTE_NOTHING_TO_DO);
		}
		$share = $this->links->find($context->detection);
		if ($share === null) {
			return ResponseOutcome::skipped(ResponseOutcome::NOTE_NOTHING_TO_DO);
		}
		$result = $this->alerts->alert($context->detection, $share);
		if ($result['recipients'] === []) {
			return ResponseOutcome::skipped(ResponseOutcome::NOTE_NOTHING_TO_DO, $result);
		}
		return ResponseOutcome::done($result);
	}

	#[\Override]
	public function describeAction(array $action, IL10N $l, DateFormatter $dates): array {
		$ref = is_array($action['ref'] ?? null) ? $action['ref'] : [];
		$recipients = array_values(array_filter((array)($ref['recipients'] ?? []), 'is_string'));
		$sentences = [$l->n(
			'Told %s, who manages the share, with a notification that offers "Open share settings" and "Disable link".',
			'Told %s, who manage the share, with a notification that offers "Open share settings" and "Disable link".',
			count($recipients),
			[implode(', ', $recipients)],
		)];
		if (isset($ref['emails'])) {
			$emails = (int)$ref['emails'];
			$sentences[] = $emails > 0
				? $l->n('%n email was sent as well.', '%n emails were sent as well.', $emails)
				: $l->t('No email was sent: there is no email address, or sending failed.');
			return $sentences;
		}
		$sentences[] = match ($ref['email'] ?? null) {
			ShareOwnerAlerts::EMAIL_QUEUED => $l->t('An email was queued as well.'),
			ShareOwnerAlerts::EMAIL_LIMITED => $l->t('No email was sent: the limit of emails to users within the hour was reached.'),
			default => $l->t('No email was sent: there is no email address.'),
		};
		return $sentences;
	}
}
