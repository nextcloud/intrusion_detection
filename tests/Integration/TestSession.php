<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\Session\Memory;
use OCP\Session\Exceptions\SessionNotAvailableException;

/**
 * An in-memory session whose id is a real session token, as a browser
 * session's id is.
 */
class TestSession extends Memory {
	public ?string $id = null;

	#[\Override]
	public function getId(): string {
		return $this->id ?? throw new SessionNotAvailableException('No session id in this test');
	}
}
