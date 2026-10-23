<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener\Login;

use OCA\IntrusionDetection\Guard\DeferredHits;
use OCP\User\Events\UserLoggedInEvent;

/**
 * Decides the guard hits of a request that logs in with Basic auth, an app
 * password or a Bearer token (an injection probe, a trap URL,
 * {@see DeferredHits}): the login names the user.
 */
class PayloadStep implements ILoginStep {
	public function __construct(
		private readonly DeferredHits $hits,
	) {
	}

	#[\Override]
	public static function appliesTo(LoginFacts $facts): bool {
		return $facts->event instanceof UserLoggedInEvent && DeferredHits::isPending($facts->context);
	}

	#[\Override]
	public function handle(LoginFacts $facts): void {
		$this->hits->resolve($facts->user);
	}
}
