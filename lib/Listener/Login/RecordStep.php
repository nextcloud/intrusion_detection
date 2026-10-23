<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener\Login;

use OCA\IntrusionDetection\Db\LoginMapper;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\User\Events\UserLoggedInEvent;

/**
 * Records which account logged in from which address, once per hour, for
 * the shared-address safety valve: an address many people log in from is
 * not blocked.
 *
 * Core reports a login for every WebDAV, CalDAV or app request with Basic
 * or Bearer credentials. With a memory cache only the first one per
 * address, account, credential and hour reaches the database
 * ({@see \OCA\IntrusionDetection\Login\LoginGate}); without one, every one
 * costs a read of the row, and the insert only when it is missing.
 */
class RecordStep implements ILoginStep {
	public function __construct(
		private readonly LoginMapper $logins,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	#[\Override]
	public static function appliesTo(LoginFacts $facts): bool {
		return $facts->event instanceof UserLoggedInEvent && $facts->isRecorded();
	}

	#[\Override]
	public function handle(LoginFacts $facts): void {
		$source = $facts->source;
		if ($source === null || $facts->isBypassListed()) {
			return;
		}
		$hour = intdiv($this->timeFactory->getTime(), 3600);
		$first = $facts->firstOfTheHour();
		if ($first === false || ($first === null && $this->logins->exists($source->ipKey, $facts->uid(), $hour))) {
			return;
		}
		$this->logins->record($source->ipKey, $source->netKey, $facts->uid(), $hour);
	}
}
