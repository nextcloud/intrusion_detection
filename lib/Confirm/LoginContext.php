<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

use OCA\IntrusionDetection\Net\SourceKey;
use OCP\IUser;

/**
 * One successful password login, as the step-up reasons see it. It holds
 * the password's fingerprints, never the password: the fingerprints are
 * compared with the flags of sprayed passwords and never stored.
 */
final class LoginContext {
	/**
	 * @param bool $interactive through the login form, as opposed to an app or script sending the password (Basic auth)
	 * @param list<string> $passwordCandidates hex fingerprints of the password (today's, and yesterday's after midnight)
	 * @param bool $passwordFlagged whether one of them is flagged as sprayed
	 */
	public function __construct(
		public readonly IUser $user,
		public readonly ?SourceKey $source,
		public readonly bool $interactive,
		public readonly ?string $userAgent,
		#[\SensitiveParameter]
		public readonly array $passwordCandidates,
		public readonly bool $passwordFlagged,
	) {
	}

	public function uid(): string {
		return $this->user->getUID();
	}

	/**
	 * @return array<string, mixed>
	 */
	public function __debugInfo(): array {
		return ['uid' => $this->user->getUID(), 'source' => $this->source?->ip, 'interactive' => $this->interactive];
	}
}
