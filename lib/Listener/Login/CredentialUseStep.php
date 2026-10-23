<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener\Login;

use OCA\IntrusionDetection\Check\Checks\TokenConcurrentUse\CredentialUse;
use OCA\IntrusionDetection\Check\Checks\TokenConcurrentUse\CredentialUseResolver;
use OCP\User\Events\UserLoggedInEvent;

/**
 * Tells the credential check that the request logged in, while a
 * credential the guard noted waits to be learned about.
 */
class CredentialUseStep implements ILoginStep {
	public function __construct(
		private readonly CredentialUseResolver $resolver,
	) {
	}

	#[\Override]
	public static function appliesTo(LoginFacts $facts): bool {
		$use = $facts->context->get(CredentialUseResolver::CONTEXT_KEY);
		return $facts->event instanceof UserLoggedInEvent && $use instanceof CredentialUse && $use->needsResolution();
	}

	#[\Override]
	public function handle(LoginFacts $facts): void {
		$event = $facts->event;
		if ($event instanceof UserLoggedInEvent) {
			$this->resolver->loggedIn($facts->user, $event->getLoginName(), $event->isTokenLogin());
		}
	}
}
