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
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\Response\IResponseHandler;
use OCA\IntrusionDetection\Response\ResponseContext;
use OCA\IntrusionDetection\Response\ResponseOutcome;
use OCP\IL10N;

/**
 * Flags the detection's sources, and the networks it blocks as a whole, so
 * that successful logins from them need extra confirmation for a while.
 * Shared addresses and a suspected reverse proxy are not flagged
 * ({@see \OCA\IntrusionDetection\Response\BanExemptions::forFlag()}).
 */
class FlagSourceHandler implements IResponseHandler, IDescribesAction {
	public function __construct(
		private readonly FlaggedSources $flags,
	) {
	}

	#[\Override]
	public function type(): ResponseType {
		return ResponseType::FlagSource;
	}

	#[\Override]
	public function apply(ResponseContext $context): ResponseOutcome {
		$targets = $context->draft->sources();
		$networks = $context->draft->networkBanTargets();
		if ($targets === [] && $networks === []) {
			return ResponseOutcome::skipped(ResponseOutcome::NOTE_NOTHING_TO_DO);
		}
		$until = 0;
		$flagged = 0;
		foreach ($targets as $target) {
			$expires = $this->flags->flagSource($target, FlaggedSources::REASON_ATTACK, $context->detection->getId());
			if ($expires !== null) {
				$until = $expires;
				$flagged++;
			}
		}
		$networksFlagged = 0;
		foreach ($networks as $member) {
			if ($this->flags->flagNetwork($member, FlaggedSources::REASON_ATTACK, $context->detection->getId())) {
				$networksFlagged++;
			}
		}
		if ($flagged === 0 && $networksFlagged === 0) {
			return ResponseOutcome::skipped(ResponseOutcome::NOTE_HELD_BACK, ['sources' => 0, 'until' => 0, 'held_back' => true]);
		}
		return ResponseOutcome::done(['sources' => $flagged, 'until' => $until]);
	}

	#[\Override]
	public function describeAction(array $action, IL10N $l, DateFormatter $dates): array {
		$ref = is_array($action['ref'] ?? null) ? $action['ref'] : [];
		if (($ref['held_back'] ?? false) === true) {
			return [$l->t('Logins from this address do not need extra confirmation: many people log in from it, or it may be a reverse proxy.')];
		}
		$until = (int)($ref['until'] ?? 0);
		return [$until > 0
			? $l->t('Successful logins from this address need extra confirmation until %s.', [$dates->dateTime($until)])
			: $l->t('Successful logins from this address need extra confirmation for a while.')];
	}
}
