<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\SharedAddress;

use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Signal\BlockHeldBack;
use OCA\IntrusionDetection\Signal\IDetector;
use OCA\IntrusionDetection\Signal\ISignal;

/**
 * Tells the administrators about a block the ban response held back.
 *
 * @template-implements IDetector<BlockHeldBack>
 */
class SharedAddressDetector implements IDetector {
	/**
	 * @param BlockHeldBack $signal
	 * @return list<DetectionDraft>
	 */
	#[\Override]
	public function detect(#[\SensitiveParameter] ISignal $signal, ModeState $mode): iterable {
		return [SharedAddress::draft($signal->target, $signal->users, $signal->wantedBy, $signal->proxy)];
	}
}
