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
use OCA\IntrusionDetection\Response\SessionKiller;
use OCP\IL10N;

/**
 * Ends the detection's session (the draft's `sessionTokenId`) and the app
 * passwords that came with it; see {@see SessionKiller}. The action records
 * the ids and names of what was ended.
 */
class KillSessionHandler implements IResponseHandler, IDescribesAction {
	public function __construct(
		private readonly SessionKiller $killer,
	) {
	}

	#[\Override]
	public function type(): ResponseType {
		return ResponseType::KillSession;
	}

	#[\Override]
	public function apply(ResponseContext $context): ResponseOutcome {
		$draft = $context->draft;
		if ($draft->uid === null || ($draft->sessionTokenId === null && $draft->source === null)) {
			return ResponseOutcome::skipped(ResponseOutcome::NOTE_NOTHING_TO_DO);
		}
		$result = $this->killer->kill($draft->uid, $draft->sessionTokenId, $draft->source?->ip, (string)$context->detection->getId());
		if ($result['session'] === null && $result['tokens'] === []) {
			// Already ended, e.g. by an earlier hit of a merged detection: keep what that one recorded.
			return ResponseOutcome::skipped(ResponseOutcome::NOTE_NOTHING_TO_DO);
		}
		return ResponseOutcome::done($result);
	}

	#[\Override]
	public function describeAction(array $action, IL10N $l, DateFormatter $dates): array {
		$ref = is_array($action['ref'] ?? null) ? $action['ref'] : [];
		$sentences = [];
		if (is_array($ref['session'] ?? null)) {
			$sentences[] = $l->t('Ended the session "%1$s" (id %2$s).', [(string)($ref['session']['name'] ?? ''), (string)($ref['session']['id'] ?? '')]);
		}
		if (($ref['loggedOut'] ?? false) === true) {
			$sentences[] = $l->t('The request that triggered this was logged out at once.');
		}
		$names = [];
		foreach ((array)($ref['tokens'] ?? []) as $token) {
			if (is_array($token)) {
				$names[] = '"' . (string)($token['name'] ?? '') . '"';
			}
		}
		if ($names !== []) {
			$sentences[] = $l->n(
				'Revoked %n app password created from that session, or from the same address within the hour: %s.',
				'Revoked %n app passwords created from that session, or from the same address within the hour: %s.',
				count($names),
				[implode(', ', $names)],
			);
		}
		return $sentences;
	}
}
