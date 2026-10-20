<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Event;

use OCA\IntrusionDetection\Db\Detection;
use OCP\EventDispatcher\Event;

/**
 * A check found something, and the responses have run (or were recorded as
 * "would have" in Observe mode).
 */
class DetectionCreatedEvent extends Event {
	public function __construct(
		private readonly Detection $detection,
	) {
		parent::__construct();
	}

	public function getDetection(): Detection {
		return $this->detection;
	}
}
