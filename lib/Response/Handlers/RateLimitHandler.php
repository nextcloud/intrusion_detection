<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Response\Handlers;

use OCA\IntrusionDetection\Check\Checks\DirectoryScraping;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Explain\IDescribesAction;
use OCA\IntrusionDetection\Response\IResponseHandler;
use OCA\IntrusionDetection\Response\ResponseContext;
use OCA\IntrusionDetection\Response\ResponseOutcome;
use OCP\IL10N;

/**
 * Records that the account's requests of one kind are refused until the
 * end of the counting window. The refusal itself happens on each request,
 * where the counter is ({@see \OCA\IntrusionDetection\Check\Checks\DirectoryScrapingDetector}),
 * as long as the check acts with this response; nothing is stored here.
 */
class RateLimitHandler implements IResponseHandler, IDescribesAction {
	#[\Override]
	public function type(): ResponseType {
		return ResponseType::RateLimit;
	}

	#[\Override]
	public function apply(ResponseContext $context): ResponseOutcome {
		$facts = $context->draft->facts;
		$group = $facts['group'] ?? null;
		$until = $facts['until'] ?? null;
		if ($context->draft->uid === null || !is_string($group) || !is_int($until)) {
			return ResponseOutcome::skipped(ResponseOutcome::NOTE_NOTHING_TO_DO);
		}
		return ResponseOutcome::done(['group' => $group, 'until' => $until]);
	}

	#[\Override]
	public function describeAction(array $action, IL10N $l, DateFormatter $dates): array {
		$ref = is_array($action['ref'] ?? null) ? $action['ref'] : [];
		$group = is_string($ref['group'] ?? null) ? $ref['group'] : '';
		$until = is_int($ref['until'] ?? null) ? $ref['until'] : null;
		if ($until === null) {
			return [];
		}
		return [$l->t('Further %1$s of the account were refused until %2$s.', [DirectoryScraping::groupLabel($group, $l), $dates->time($until)])];
	}
}
