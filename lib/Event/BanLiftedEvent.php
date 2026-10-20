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
 * A block was lifted by an administrator before it expired.
 */
class BanLiftedEvent extends Event {
	public function __construct(
		private readonly Ban $ban,
	) {
		parent::__construct();
	}

	public function getBan(): Ban {
		return $this->ban;
	}
}
