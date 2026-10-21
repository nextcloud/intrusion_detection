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
use OCA\IntrusionDetection\Response\IResponseHandler;
use OCA\IntrusionDetection\Response\ResponseContext;
use OCA\IntrusionDetection\Response\ResponseOutcome;
use OCA\IntrusionDetection\Sensitive\RiskySessions;
use OCA\IntrusionDetection\Sensitive\SensitiveSession;
use OCA\IntrusionDetection\SessionState\CurrentSession;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCP\IL10N;
use OCP\IUserSession;

/**
 * Makes the session a detection is about risky for the rest of its life:
 * every further sensitive action needs a fresh confirmation (concept
 * section 11.13).
 *
 * - The current request's own session is marked in the PHP session.
 * - Another session (a detection that looks back, or one made in a
 *   background job) is marked by its token id ({@see RiskySessions}).
 *
 * Marking twice changes nothing, so a merged detection may run it again.
 * The ref holds the token id, never the token.
 */
class ConfirmSensitiveHandler implements IResponseHandler, IDescribesAction {
	public const NOTE_NO_SESSION = 'no_session';

	public function __construct(
		private readonly SessionState $state,
		private readonly SensitiveSession $sensitive,
		private readonly RiskySessions $marks,
		private readonly CurrentSession $currentSession,
		private readonly IUserSession $userSession,
	) {
	}

	#[\Override]
	public function type(): ResponseType {
		return ResponseType::ConfirmSensitive;
	}

	#[\Override]
	public function apply(ResponseContext $context): ResponseOutcome {
		$uid = $context->draft->uid;
		if ($uid === null) {
			return ResponseOutcome::skipped(ResponseOutcome::NOTE_NOTHING_TO_DO);
		}
		$tokenId = $context->draft->sessionTokenId;
		$ownSession = $this->userSession->getUser()?->getUID() === $uid;
		$current = $ownSession ? $this->currentSession->tokenId() : null;
		if ($ownSession && ($tokenId === null || $tokenId === $current)) {
			$this->sensitive->markRisky($this->state, $uid, $context->definition->id, $context->detection->getId());
			return ResponseOutcome::done(['session' => $current]);
		}
		if ($tokenId === null) {
			return ResponseOutcome::skipped(self::NOTE_NO_SESSION);
		}
		$this->marks->mark($tokenId, $uid, $context->definition->id, $context->detection->getId());
		return ResponseOutcome::done(['session' => $tokenId]);
	}

	#[\Override]
	public function describeAction(array $action, IL10N $l, DateFormatter $dates): array {
		if (($action['note'] ?? null) === self::NOTE_NO_SESSION) {
			return [$l->t('No session could be told apart, so no session was asked to confirm sensitive actions.')];
		}
		return [$l->t('For the rest of the session, sensitive actions such as changing the email address or password, removing a second factor or creating app passwords need a fresh confirmation.')];
	}
}
