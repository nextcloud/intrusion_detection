<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Response;

use OCA\IntrusionDetection\Check\ResponseType;

/**
 * Carries out one response type. Implementations are listed in
 * {@see ResponseEngine::HANDLERS} and must be idempotent: a merged detection
 * runs its responses again.
 */
interface IResponseHandler {
	public function type(): ResponseType;

	public function apply(ResponseContext $context): ResponseOutcome;
}
