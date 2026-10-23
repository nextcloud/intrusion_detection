<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Signal;

use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Detection\DetectionDraft;

/**
 * Judges signals for one check, under whose id it is listed in
 * {@see \OCA\IntrusionDetection\Check\CheckRegistry::DETECTORS}: reads what
 * it needs and returns what it found as drafts. It never records or answers a detection and never reads
 * its check's mode: {@see SignalDispatcher} builds it only while the check
 * runs, hands it the mode, and passes the drafts to the response engine.
 *
 * A detector that needs the stored detection of a draft (to remember its id,
 * or to act on its outcome) is a generator: each `yield $draft` returns the
 * stored detection, or null when the check was off.
 *
 * @template T of ISignal
 */
interface IDetector {
	/**
	 * @param T $signal
	 * @param ModeState $mode the mode the check runs in, for detectors whose logic depends on it
	 * @return iterable<int, DetectionDraft>
	 */
	public function detect(#[\SensitiveParameter] ISignal $signal, ModeState $mode): iterable;
}
