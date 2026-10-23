<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

use OCA\IntrusionDetection\Login\LoginContext;

/**
 * One reason why a password login needs extra confirmation. Providers are
 * listed in {@see StepUpReasons::PROVIDERS} and asked once per successful
 * password login, so applies() must be cheap: cached reads, at most one
 * indexed query, nothing at all while the feature behind it is off.
 */
interface IStepUpReason {
	/**
	 * The policy of this reason. Static, so that the settings can be built
	 * without creating the provider.
	 */
	public static function policy(): StepUpPolicy;

	public function applies(LoginContext $login): bool;
}
