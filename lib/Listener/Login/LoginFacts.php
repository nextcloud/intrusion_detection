<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener\Login;

use OCA\IntrusionDetection\Confirm\LoginConfirmation;
use OCA\IntrusionDetection\KnownDevice\KnownDevice;
use OCA\IntrusionDetection\Login\LoginKind;
use OCA\IntrusionDetection\Login\RequestContext;
use OCA\IntrusionDetection\Net\SourceKey;
use OCP\IUser;
use OCP\User\Events\UserLoggedInEvent;
use OCP\User\Events\UserLoggedInWithCookieEvent;

/**
 * What the login steps know about one successful login, worked out once:
 * how it logged in, who, from where, whether it is recorded this hour,
 * and what the earlier steps found. The step-up step sets the
 * confirmation, the known-device step the device, for the steps after them.
 */
final class LoginFacts {
	/** What the step-up decided; null when it did not run */
	public ?LoginConfirmation $confirmation = null;
	/** The account's remembered device the login came from */
	public ?KnownDevice $device = null;

	private ?bool $firstOfTheHour = null;
	private bool $gateAsked = false;
	private ?bool $bypassListed = null;
	private ?bool $mayResume = null;

	/**
	 * @param \Closure(): ?bool $gate whether this is the first login of the hour with its credential from its address; null when it cannot tell
	 * @param \Closure(): bool $bypass whether the address is on the brute-force allowlist
	 * @param \Closure(): bool $resumable whether a session that was never confirmed could come back now
	 */
	public function __construct(
		public readonly UserLoggedInEvent|UserLoggedInWithCookieEvent $event,
		public readonly LoginKind $kind,
		public readonly IUser $user,
		public readonly ?SourceKey $source,
		public readonly string $userAgent,
		public readonly RequestContext $context,
		private readonly \Closure $gate,
		private readonly \Closure $bypass,
		private readonly \Closure $resumable,
	) {
	}

	public function uid(): string {
		return $this->user->getUID();
	}

	/**
	 * Whether this is the account's first login with its credential from
	 * its address in the hour ({@see \OCA\IntrusionDetection\Login\LoginGate});
	 * null without an address or a memory cache.
	 */
	public function firstOfTheHour(): ?bool {
		if (!$this->gateAsked) {
			$this->gateAsked = true;
			$this->firstOfTheHour = $this->source === null ? null : ($this->gate)();
		}
		return $this->firstOfTheHour;
	}

	/**
	 * Whether what records logins runs: always for a browser, and for an
	 * app that logs in with every request only with its first login of
	 * the hour, or when that cannot be told.
	 */
	public function isRecorded(): bool {
		return !$this->kind->isClient() || $this->firstOfTheHour() !== false;
	}

	public function isBypassListed(): bool {
		return $this->bypassListed ??= $this->source !== null && ($this->bypass)();
	}

	/**
	 * Whether a session that comes back could resume a login that was never confirmed.
	 */
	public function mayResume(): bool {
		return $this->mayResume ??= ($this->resumable)();
	}
}
