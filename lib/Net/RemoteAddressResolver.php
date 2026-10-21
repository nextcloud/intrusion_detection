<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Net;

use OCP\IRequest;
use OCP\Security\Bruteforce\IThrottler;

/**
 * The client address of the current request, as core resolves it (honouring
 * `trusted_proxies` and `forwarded_for_headers`), and the rules about which
 * addresses the app may act on.
 */
class RemoteAddressResolver {
	public function __construct(
		private readonly IRequest $request,
		private readonly IThrottler $throttler,
		private readonly ServerAddresses $servers,
	) {
	}

	public function current(): ?SourceKey {
		return SourceKey::tryFromIp($this->request->getRemoteAddress());
	}

	/**
	 * Addresses on the brute-force allowlist are never recorded, blocked or flagged.
	 */
	public function isBypassListed(SourceKey $source): bool {
		return $this->throttler->isBypassListed($source->ip);
	}

	/**
	 * Loopback and the server's own addresses ({@see ServerAddresses}) are
	 * never blocked: that would lock out cron, health checks and the server
	 * itself.
	 */
	public function isNeverBlocked(SourceKey $source): bool {
		return $source->isLoopback() || $this->servers->contains($source);
	}

	/**
	 * Remember the address this web request came in on as one of the
	 * server's own, for cron and occ ({@see ServerAddresses::observe()}).
	 */
	public function observeServerAddress(): void {
		$this->servers->observe();
	}

	/**
	 * Whether the app should ignore this source entirely.
	 */
	public function isIgnored(SourceKey $source): bool {
		return $this->isBypassListed($source) || $this->isNeverBlocked($source);
	}
}
