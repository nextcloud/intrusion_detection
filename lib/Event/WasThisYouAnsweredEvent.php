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
 * A user answered "Was this you?" about one of their detections, after the
 * answer took effect. Listeners can follow up, for example by starting a
 * guide that helps securing the account after "No, it was not me".
 */
class WasThisYouAnsweredEvent extends Event {
	/**
	 * @param Detection::VERDICT_* $verdict
	 */
	public function __construct(
		private readonly Detection $detection,
		private readonly string $verdict,
	) {
		parent::__construct();
	}

	public function getDetection(): Detection {
		return $this->detection;
	}

	/**
	 * @return Detection::VERDICT_*
	 */
	public function getVerdict(): string {
		return $this->verdict;
	}

	public function isDenied(): bool {
		return $this->verdict === Detection::VERDICT_DENIED;
	}
}
