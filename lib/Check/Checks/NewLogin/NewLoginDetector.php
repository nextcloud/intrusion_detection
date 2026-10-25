<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\NewLogin;

use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Confirm\LoginDetections;
use OCA\IntrusionDetection\Confirm\SecondFactors;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Detection\CommonFacts;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\KnownDevice\DeviceLabel;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\LoginHistory\SignInHabits;
use OCA\IntrusionDetection\LoginHistory\SignInHistory;
use OCA\IntrusionDetection\Notification\UserMessages;
use OCA\IntrusionDetection\Signal\IDetector;
use OCA\IntrusionDetection\Signal\ISignal;
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\AppFramework\Utility\ITimeFactory;

/**
 * Judges a person's login that nothing asked or told them about: it is a
 * new login when the account's own history ({@see SignInHabits}) finds both
 * its network and its kind of device new. Never:
 *
 * - for an account with a second factor, which is asked for it next;
 * - when another detection of the same login already tells the user;
 * - while the account's login history does not reach back further than
 *   the habit window: a new account, a server that installed the app less
 *   than 30 days ago, or a retention shorter than that.
 *
 * At most once per device: a login that goes through makes its kind of
 * device usual for the next 30 days. A check that only notifies acts even
 * in learning mode; this one only records then, since nobody should be
 * told about their devices while the app is still being set up.
 *
 * @template-implements IDetector<UnfamiliarLogin>
 */
class NewLoginDetector implements IDetector {
	public function __construct(
		private readonly SignInHistory $signIns,
		private readonly LoginHistory $history,
		private readonly SecondFactors $secondFactors,
		private readonly LoginDetections $loginDetections,
		private readonly DetectionMapper $detections,
		private readonly UserMessages $messages,
		private readonly AppSettings $settings,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * @param UnfamiliarLogin $signal
	 * @return list<DetectionDraft>
	 */
	#[\Override]
	public function detect(#[\SensitiveParameter] ISignal $signal, ModeState $mode): iterable {
		$user = $signal->user;
		$uid = $user->getUID();
		if ($this->secondFactors->has($user) || $this->toldAlready($uid)) {
			return [];
		}
		$now = $this->timeFactory->getTime();
		[, $habits] = $this->signIns->read($user, $now, 0);
		$labels = $habits->labels($now, $signal->source->netKey, $signal->userAgent, false, true);
		if (!in_array(SignInHabits::NEW_NETWORK, $labels, true) || !in_array(SignInHabits::NEW_DEVICE, $labels, true)) {
			return [];
		}
		if ($this->history->forUser($uid, 0, $now - SignInHabits::WINDOW, 1) === []) {
			return [];
		}
		[$family, $platform] = DeviceLabel::parse($signal->userAgent);
		return [new DetectionDraft(
			checkId: NewLogin::ID,
			source: $signal->source,
			uid: $uid,
			facts: new NewLoginFacts($family, $platform, $signal->typedPassword, new CommonFacts(first: $now, last: $now)),
			merge: DetectionDraft::MERGE_SOURCE_USER,
			userAgent: $signal->userAgent,
			mode: $this->settings->isLearning() && $mode->acts() ? new ModeState($mode->configured, Mode::Observe, ModeState::REASON_LEARNING) : null,
		)];
	}

	/**
	 * Whether a detection the same login recorded tells the user.
	 */
	private function toldAlready(string $uid): bool {
		foreach ($this->loginDetections->waiting($uid) as $id) {
			try {
				if ($this->messages->tellsUser($this->detections->findById($id))) {
					return true;
				}
			} catch (DoesNotExistException) {
				// Deleted in the meantime: it tells nobody.
			}
		}
		return false;
	}
}
