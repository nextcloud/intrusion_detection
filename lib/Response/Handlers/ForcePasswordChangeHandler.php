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
use OCA\IntrusionDetection\Response\PasswordChangeService;
use OCA\IntrusionDetection\Response\ResponseContext;
use OCA\IntrusionDetection\Response\ResponseOutcome;
use OCP\IL10N;

/**
 * Requires the detection's account to choose a new password at its next
 * login; see {@see PasswordChangeService}.
 */
class ForcePasswordChangeHandler implements IResponseHandler, IDescribesAction {
	public function __construct(
		private readonly PasswordChangeService $passwords,
	) {
	}

	#[\Override]
	public function type(): ResponseType {
		return ResponseType::ForcePasswordChange;
	}

	#[\Override]
	public function apply(ResponseContext $context): ResponseOutcome {
		$uid = $context->draft->uid;
		if ($uid === null) {
			return ResponseOutcome::skipped(ResponseOutcome::NOTE_NOTHING_TO_DO);
		}
		$state = $this->passwords->require($uid, $context->detection->getId(), $context->definition->id);
		if ($state === PasswordChangeService::STATE_NO_USER) {
			return ResponseOutcome::skipped(ResponseOutcome::NOTE_NOTHING_TO_DO);
		}
		return ResponseOutcome::done(['uid' => $uid, 'state' => $state]);
	}

	#[\Override]
	public function describeAction(array $action, IL10N $l, DateFormatter $dates): array {
		$ref = is_array($action['ref'] ?? null) ? $action['ref'] : [];
		$uid = (string)($ref['uid'] ?? '');
		return [($ref['state'] ?? null) === PasswordChangeService::STATE_EXTERNAL
			? $l->t('The password of %s is managed outside Nextcloud, so it cannot be changed here. The administrators were asked to reset it in that directory.', [$uid])
			: $l->t('%s must choose a new password at the next login. Until then, logins with the password from apps and scripts are refused; app passwords keep working.', [$uid])];
	}
}
