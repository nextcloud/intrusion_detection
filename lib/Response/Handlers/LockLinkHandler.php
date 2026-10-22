<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Response\Handlers;

use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Explain\IDescribesAction;
use OCA\IntrusionDetection\Response\IResponseHandler;
use OCA\IntrusionDetection\Response\ResponseContext;
use OCA\IntrusionDetection\Response\ResponseOutcome;
use OCA\IntrusionDetection\Takeover\LockLinks;
use OCP\IL10N;
use OCP\IUserManager;

/**
 * Emails the previous address of an email change a one-time link that
 * locks the account (concept section 11.15). Only for detections whose facts
 * name an email change with a previous address (`emailChangeId`); at most
 * one link per detection, so a merged detection does not send another.
 */
class LockLinkHandler implements IResponseHandler, IDescribesAction {
	public const NOTE_NO_EMAIL_CHANGE = 'no_email_change';

	public function __construct(
		private readonly LockLinks $links,
		private readonly IUserManager $userManager,
	) {
	}

	#[\Override]
	public function type(): ResponseType {
		return ResponseType::LockLink;
	}

	#[\Override]
	public function apply(ResponseContext $context): ResponseOutcome {
		$facts = $context->detection->getExplanationData()['facts'] ?? [];
		$changeId = is_array($facts) ? ($facts['emailChangeId'] ?? null) : null;
		$user = $context->draft->uid === null ? null : $this->userManager->get($context->draft->uid);
		if (!is_int($changeId) || $user === null) {
			// Recorded as handled with a note, so the narrative says why nothing was sent.
			return ResponseOutcome::done(null, self::NOTE_NO_EMAIL_CHANGE);
		}
		$result = $this->links->send($user, $changeId, $context->detection->getId());
		return match ($result['state']) {
			LockLinks::SENT => ResponseOutcome::done(['sentTo' => $result['sentTo'] ?? null, 'link' => $result['link'] ?? null]),
			// Sent for an earlier hit: keep what that one recorded.
			LockLinks::ALREADY_SENT => ResponseOutcome::skipped(ResponseOutcome::NOTE_NOTHING_TO_DO),
			LockLinks::MAIL_FAILED => ResponseOutcome::done(['sentTo' => $result['sentTo'] ?? null], LockLinks::MAIL_FAILED),
			default => ResponseOutcome::done(null, LockLinks::NO_PREVIOUS_ADDRESS),
		};
	}

	#[\Override]
	public function describeAction(array $action, IL10N $l, DateFormatter $dates): array {
		$ref = is_array($action['ref'] ?? null) ? $action['ref'] : [];
		$sentTo = (string)($ref['sentTo'] ?? '');
		return match ($action['note'] ?? null) {
			self::NOTE_NO_EMAIL_CHANGE => [$l->t('No lock link was sent: the email address was not changed.')],
			LockLinks::NO_PREVIOUS_ADDRESS => [$l->t('No lock link was sent: the account had no email address before the change.')],
			LockLinks::MAIL_FAILED => [$l->t('The lock link to the previous address %s could not be sent.', [$sentTo])],
			default => [$l->t('A one-time link to lock the account was emailed to the previous address %s. It works for 7 days.', [$sentTo])],
		};
	}
}
