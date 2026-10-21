<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\AdminChange;

use OCP\IUserSession;

/**
 * Who made a change in the current process: the logged-in user, occ, a
 * background job started on the command line, or nobody known.
 */
class ActorResolver {
	public const OCC = 'occ';
	public const CRON = 'cron';
	public const UNKNOWN = 'unknown';

	public function __construct(
		private readonly IUserSession $userSession,
	) {
	}

	/**
	 * @return string a uid, or one of the constants
	 */
	public function actor(): string {
		if ($this->isConsole()) {
			return self::OCC;
		}
		if ($this->isCommandLine()) {
			return self::CRON;
		}
		return $this->userSession->getUser()?->getUID() ?? self::UNKNOWN;
	}

	/**
	 * Whether this process runs on the server's command line (occ or cron.php):
	 * whoever starts it already controls the server.
	 */
	public function isCommandLine(): bool {
		return PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg';
	}

	/**
	 * Whether this process is occ; console.php defines OC_CONSOLE.
	 */
	public function isConsole(): bool {
		return $this->isCommandLine() && defined('OC_CONSOLE');
	}

	public static function isPerson(string $actor): bool {
		return !in_array($actor, [self::OCC, self::CRON, self::UNKNOWN], true);
	}
}
