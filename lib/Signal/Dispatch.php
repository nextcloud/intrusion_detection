<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Signal;

use OCA\IntrusionDetection\Db\Detection;

/**
 * What the detectors of one signal found.
 */
final class Dispatch {
	/**
	 * @param list<Detection> $detections the stored detections, in the order they were found
	 * @param bool $stopped a final detection answered the signal, and the later detectors did not run
	 */
	public function __construct(
		public readonly array $detections,
		public readonly bool $stopped,
	) {
	}
}
