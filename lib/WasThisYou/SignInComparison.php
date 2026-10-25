<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\WasThisYou;

use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\KnownDevice\DeviceLabel;
use OCA\IntrusionDetection\LoginHistory\SignInHabits;
use OCA\IntrusionDetection\Notification\UserMessages;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\IL10N;
use OCP\IUser;

/**
 * Puts a "Was this you?" question next to the account's habit, in plain
 * words: what the event was ("Firefox on Windows, new network, 3:12 AM")
 * and how the user usually logs in ("You usually log in with Chrome on
 * macOS from your usual network"). Built from the event's own address,
 * device and time and the account's {@see SignInHabits}, in the user's
 * language and time zone; it stores nothing.
 *
 * @psalm-import-type IntrusionDetectionSignInComparison from ResponseDefinitions
 */
class SignInComparison {
	/** Logins this shortly before an event can be its own login: they are no habit */
	public const OWN_LOGIN = 300;

	public function __construct(
		private readonly UserMessages $messages,
		private readonly DateFormatter $dates,
	) {
	}

	/**
	 * @return ?IntrusionDetectionSignInComparison null when the event names neither a device nor a network to compare
	 */
	public function describe(Detection $detection, IUser $user, SignInHabits $habits): ?array {
		$userAgent = $detection->getExplanationData()['userAgent'] ?? null;
		$userAgent = is_string($userAgent) ? $userAgent : null;
		[$family] = DeviceLabel::parse($userAgent);
		$browser = $family !== DeviceLabel::OTHER && !str_starts_with($family, 'nextcloud_');
		$at = $detection->getCreatedTime();
		$labels = $habits->labels($at, $detection->getNetKey(), $userAgent, false, $browser, self::OWN_LOGIN);
		$usual = $habits->usual($at, self::OWN_LOGIN);
		$l = $this->messages->l10nFor($user);
		return $this->messages->asReader($user, $l, function () use ($l, $at, $userAgent, $labels, $usual): ?array {
			$seen = [];
			$device = DeviceLabel::describe($userAgent, $l);
			if ($device !== null) {
				$seen[] = $device;
			}
			$newNetwork = in_array(SignInHabits::NEW_NETWORK, $labels, true);
			if ($newNetwork) {
				$seen[] = $l->t('new network');
			} elseif (in_array(SignInHabits::USUAL_NETWORK, $labels, true)) {
				$seen[] = $l->t('your usual network');
			}
			if ($seen === []) {
				return null;
			}
			$time = $this->dates->time($at);
			$seen[] = in_array(SignInHabits::UNUSUAL_HOUR, $labels, true) ? $l->t('%s, an unusual hour for you', [$time]) : $time;
			return [
				'seen' => implode(', ', $seen),
				'usually' => $usual === null ? null : self::usually($usual, $newNetwork, $l),
			];
		});
	}

	/**
	 * @param array{family: string, platform: string, networks: int} $usual
	 */
	private static function usually(array $usual, bool $newNetwork, IL10N $l): string {
		$device = DeviceLabel::translated($usual['family'], $usual['platform'], $l);
		if (!$newNetwork) {
			return $l->t('You usually log in with %s.', [$device]);
		}
		return $l->n(
			'You usually log in with %1$s from your usual network.',
			'You usually log in with %1$s from your usual networks.',
			max(1, $usual['networks']),
			[$device],
		);
	}
}
