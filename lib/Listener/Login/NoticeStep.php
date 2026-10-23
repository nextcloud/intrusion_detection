<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener\Login;

use OCA\IntrusionDetection\Notification\LoginNotices;

/**
 * Marks the session of a person for the security notice of users
 * Nextcloud cannot reach by email (concept section 11.1).
 */
class NoticeStep implements ILoginStep {
	public function __construct(
		private readonly LoginNotices $notices,
	) {
	}

	#[\Override]
	public static function appliesTo(LoginFacts $facts): bool {
		return $facts->kind->isInteractive() && !$facts->isBypassListed();
	}

	#[\Override]
	public function handle(LoginFacts $facts): void {
		$this->notices->atLogin($facts->uid(), $facts->device);
	}
}
