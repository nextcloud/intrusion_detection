<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Event;

use OCA\IntrusionDetection\Db\Ban;
use OCP\EventDispatcher\Event;

/**
 * An address or network was blocked, or an existing block was raised to a higher level.
 */
class BanCreatedEvent extends Event {
	public function __construct(
		private readonly Ban $ban,
		private readonly bool $raised = false,
	) {
		parent::__construct();
	}

	public function getBan(): Ban {
		return $this->ban;
	}

	/**
	 * Whether an existing block was raised rather than a new one created.
	 */
	public function isRaised(): bool {
		return $this->raised;
	}
}
