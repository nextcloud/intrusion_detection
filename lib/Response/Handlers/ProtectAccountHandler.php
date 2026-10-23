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
use OCA\IntrusionDetection\Response\AccountProtection;
use OCA\IntrusionDetection\Response\IResponseHandler;
use OCA\IntrusionDetection\Response\ResponseContext;
use OCA\IntrusionDetection\Response\ResponseOutcome;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IL10N;

/**
 * Puts the detection's account under extra protection for the check's
 * `protect_duration` (one day by default), or extends a running protection,
 * so that the protection ends that long after the last failure.
 */
class ProtectAccountHandler implements IResponseHandler, IDescribesAction {
	/** Used for checks without a `protect_duration` parameter */
	public const DEFAULT_DURATION = 86400;

	public function __construct(
		private readonly AccountProtection $protection,
		private readonly CheckSettings $settings,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	#[\Override]
	public function type(): ResponseType {
		return ResponseType::ProtectAccount;
	}

	#[\Override]
	public function apply(ResponseContext $context): ResponseOutcome {
		$uid = $context->draft->uid;
		if ($uid === null) {
			return ResponseOutcome::skipped(ResponseOutcome::NOTE_NOTHING_TO_DO);
		}
		$duration = $context->definition->hasParam('protect_duration')
			? $this->settings->paramInt($context->definition->id, 'protect_duration')
			: self::DEFAULT_DURATION;
		$until = $this->protection->protect(
			$uid,
			$this->timeFactory->getTime() + $duration,
			AccountProtection::REASON_UNDER_ATTACK,
			(string)$context->detection->getId(),
		);
		return ResponseOutcome::done(['uid' => $uid, 'until' => $until]);
	}

	#[\Override]
	public function describeAction(array $action, IL10N $l, DateFormatter $dates): array {
		$ref = is_array($action['ref'] ?? null) ? $action['ref'] : [];
		$until = (int)($ref['until'] ?? 0);
		$uid = (string)($ref['uid'] ?? '');
		return [$until > 0
			? $l->t('Until %1$s, every password login to %2$s needs extra confirmation. App passwords keep working.', [$dates->dateTime($until), $uid])
			: $l->t('For a while, every password login to this account needs extra confirmation.')];
	}
}
