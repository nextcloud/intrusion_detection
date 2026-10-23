<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Response;

use OCP\IL10N;

/**
 * A block by hand of something that is never blocked: loopback, the server
 * itself, or an address on the brute-force allowlist (also inside a network).
 */
class BanRefusedException extends \InvalidArgumentException {
	public function __construct(
		public readonly string $cidr,
	) {
		parent::__construct($cidr . ' is never blocked: it is or contains a loopback address, this server or an address on the brute-force allowlist');
	}

	public function describe(IL10N $l): string {
		return $l->t('%s contains this server, a loopback address or an address on the brute-force allowlist, so it is never blocked.', [$this->cidr]);
	}
}
