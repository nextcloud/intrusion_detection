<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Detection;

/**
 * The facts of one check's detections, as a typed value: the detector
 * builds it, the check's texts read it back with the class's `fromArray()`,
 * and the simulation builds the same. A key the detection did not record
 * is left out of the stored facts, so stored rows keep their shape.
 */
interface IFacts {
	/**
	 * @return array<string, mixed> the facts as the detection stores them
	 */
	public function toArray(): array;
}
