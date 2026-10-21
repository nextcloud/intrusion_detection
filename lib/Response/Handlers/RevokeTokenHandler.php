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
use OCA\IntrusionDetection\Response\TokenRevoker;
use OCP\IL10N;

/**
 * Revokes the detection's app password or token (the draft's `tokenId`)
 * and the app passwords created with it; see {@see TokenRevoker}. When the
 * token is the detection's browser session (`tokenId` equals
 * `sessionTokenId`), revoking it ends that session, and the action says so.
 */
class RevokeTokenHandler implements IResponseHandler, IDescribesAction {
	public function __construct(
		private readonly TokenRevoker $revoker,
	) {
	}

	#[\Override]
	public function type(): ResponseType {
		return ResponseType::RevokeToken;
	}

	#[\Override]
	public function apply(ResponseContext $context): ResponseOutcome {
		$draft = $context->draft;
		if ($draft->uid === null || $draft->tokenId === null) {
			return ResponseOutcome::skipped(ResponseOutcome::NOTE_NOTHING_TO_DO);
		}
		$result = $this->revoker->revoke($draft->uid, $draft->tokenId, $context->detection->getId());
		if ($result['token'] === null && $result['tokens'] === []) {
			return ResponseOutcome::skipped(ResponseOutcome::NOTE_NOTHING_TO_DO);
		}
		if ($draft->sessionTokenId !== null && $draft->sessionTokenId === $draft->tokenId) {
			$result['session'] = true;
		}
		return ResponseOutcome::done($result);
	}

	#[\Override]
	public function describeAction(array $action, IL10N $l, DateFormatter $dates): array {
		$ref = is_array($action['ref'] ?? null) ? $action['ref'] : [];
		$sentences = [];
		if (is_array($ref['token'] ?? null)) {
			$sentences[] = ($ref['session'] ?? false) === true
				? $l->t('Ended the session "%1$s" (id %2$s).', [(string)($ref['token']['name'] ?? ''), (string)($ref['token']['id'] ?? '')])
				: $l->t('Revoked the app password "%1$s" (id %2$s).', [(string)($ref['token']['name'] ?? ''), (string)($ref['token']['id'] ?? '')]);
		}
		$count = count((array)($ref['tokens'] ?? []));
		if ($count > 0) {
			$sentences[] = $l->n('Also revoked %n app password created with it.', 'Also revoked %n app passwords created with it.', $count);
		}
		return $sentences;
	}
}
