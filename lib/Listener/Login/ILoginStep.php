<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener\Login;

/**
 * One thing the app does at a successful login, run by
 * {@see \OCA\IntrusionDetection\Listener\LoginListener} in the order of
 * its STEPS. A step that does not apply to a login is neither built nor run.
 */
interface ILoginStep {
	/**
	 * Whether the step has anything to do for this login. Static, so that a
	 * step that does not apply is not built; it must be cheap.
	 */
	public static function appliesTo(LoginFacts $facts): bool;

	/**
	 * Failures are logged by the login listener and never break the login.
	 */
	public function handle(LoginFacts $facts): void;
}
