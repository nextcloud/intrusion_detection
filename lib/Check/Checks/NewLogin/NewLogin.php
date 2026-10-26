<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\NewLogin;

use OCA\IntrusionDetection\Check\ICheck;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Definition\Category;
use OCA\IntrusionDetection\Definition\CheckDefinition;
use OCA\IntrusionDetection\Definition\CheckTexts;
use OCA\IntrusionDetection\Definition\CostClass;
use OCA\IntrusionDetection\Definition\DataKind;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Definition\Severity;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Explain\DetectionFacts;
use OCA\IntrusionDetection\Explain\IAsksWasThisYou;
use OCA\IntrusionDetection\Explain\IExplainsDetection;
use OCA\IntrusionDetection\Explain\IExplainsToUser;
use OCA\IntrusionDetection\Explain\UserNotice;
use OCA\IntrusionDetection\KnownDevice\DeviceLabel;
use OCP\IL10N;

/**
 * A person logged in from a device and a network that are both new to the
 * account, and nothing else asked or told them about it. The user is told
 * and asked "Was this you?"; "No" runs the usual answer. Raised by
 * {@see NewLoginDetector} from {@see \OCA\IntrusionDetection\Listener\Login\NewLoginStep}.
 */
final class NewLogin implements ICheck, IExplainsDetection, IExplainsToUser, IAsksWasThisYou {
	public const ID = 'new_login';

	public function __construct(
		private readonly DateFormatter $dates,
	) {
	}

	#[\Override]
	public function definition(): CheckDefinition {
		return new CheckDefinition(
			id: self::ID,
			category: Category::DevicesAndSessions,
			defaultMode: Mode::Protect,
			severity: Severity::Low,
			params: [],
			responses: [ResponseType::NotifyUser, ResponseType::NotifyAdmin],
			defaultResponses: [ResponseType::NotifyUser],
			cost: CostClass::OnLoginOnly,
			stores: [DataKind::Detections, DataKind::LoginHistory],
			texts: static fn (IL10N $l): CheckTexts => new CheckTexts(
				name: $l->t('Login from a new device and network'),
				shortName: $l->t('New login'),
				summary: $l->t('Tells users about a login from a device and a network their account has not used in the last 30 days.'),
				detects: $l->t('A login that needed no extra confirmation can still come from someone else. When both the device and the network are new to the account, the account holder is the one who can tell.'),
				decides: $l->t('Fires at a login through the login form or single sign-on when the network is not one the user trusts, no login of the account that went through came from it in the last 30 days, no such login came from the same browser on the same system, and the device is not remembered. Never when the login needed extra confirmation or another check already told the user about it, for accounts with a second factor, or while the account\'s login history is younger than 30 days, as for a new account or right after the app was installed. Once a login from a device went through, that device is no longer new for 30 days. In learning mode it only records the login.'),
				wrong: $l->t('A user on a new laptop in a hotel. They are asked "Was this you?" and can answer yes, or ignore it.'),
				data: $l->t('Detections: the account, the address and the kind of device (browser and system). Nothing new is stored to decide: it reads the login history and the trusted networks.'),
			),
			userAlertInterval: 86400,
		);
	}

	#[\Override]
	public function asksWasThisYou(Detection $detection): bool {
		return true;
	}

	#[\Override]
	public function narrative(Detection $detection, IL10N $l): array {
		$stored = DetectionFacts::of($detection);
		$facts = NewLoginFacts::fromArray($stored->facts);
		return [
			$l->t('At %1$s %2$s logged in from %3$s with %4$s. Neither the network nor this kind of device was used by the account in the 30 days before, and nothing else asked for confirmation.', [
				$this->dates->dateTime($stored->first),
				(string)$detection->getUid(),
				(string)$detection->getIp(),
				DeviceLabel::translated($facts->family, $facts->platform, $l),
			]),
		];
	}

	#[\Override]
	public function userNotice(Detection $detection, IL10N $l): UserNotice {
		$facts = NewLoginFacts::fromArray(DetectionFacts::of($detection)->facts);
		$device = DeviceLabel::translated($facts->family, $facts->platform, $l);
		return new UserNotice(
			$l->t('New login from %s', [$device]),
			[
				$l->t('Someone logged in to your account with %s, from a network your account has not used recently.', [$device]),
				$l->t('If this was you, there is nothing to do.'),
			],
			[
				$l->t('If it was not you, answer "No, it was not me". Nextcloud then ends that session and guides you through securing your account.'),
			],
		);
	}
}
