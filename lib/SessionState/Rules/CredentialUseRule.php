<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SessionState\Rules;

use OCA\IntrusionDetection\Check\Checks\TokenConcurrentUse\CredentialUse;
use OCA\IntrusionDetection\Check\Checks\TokenConcurrentUse\CredentialUseResolver;
use OCA\IntrusionDetection\Login\RequestContext;
use OCA\IntrusionDetection\Login\SessionMarkers;
use OCA\IntrusionDetection\SessionState\ISessionStateRule;
use OCA\IntrusionDetection\SessionState\RequestTarget;
use OCA\IntrusionDetection\SessionState\SessionBlock;
use Psr\Container\ContainerInterface;

/**
 * Never blocks. Once a logged-in request reaches a controller or WebDAV,
 * authentication is over: this is where the credential check learns which
 * credential logged the request in ({@see CredentialUseResolver}).
 *
 * Requests the credential guard noted nothing for cost one array lookup.
 */
class CredentialUseRule implements ISessionStateRule {
	public function __construct(
		private readonly RequestContext $context,
		private readonly ContainerInterface $container,
	) {
	}

	#[\Override]
	public function check(SessionMarkers $state, RequestTarget $target): ?SessionBlock {
		$use = $this->context->get(CredentialUseResolver::CONTEXT_KEY);
		if ($use instanceof CredentialUse && $use->needsResolution()) {
			$this->container->get(CredentialUseResolver::class)->resolve(true);
		}
		return null;
	}
}
