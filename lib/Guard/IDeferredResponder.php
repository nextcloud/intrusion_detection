<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Guard;

use OCP\IUser;
use OCP\Security\Guard\GuardDecision;

/**
 * Decides the hit of a request guard that waited until the request knew
 * whether it is logged in ({@see DeferredHits}).
 */
interface IDeferredResponder {
	/**
	 * Decide the waiting hit, if any, and keep a refusal in the request
	 * context ({@see RequestContext::refuse()}).
	 *
	 * @param ?IUser $user the logged-in user, null when the request is not logged in
	 * @return ?GuardDecision the refusal when the address is blocked now
	 */
	public function resolve(?IUser $user): ?GuardDecision;
}
