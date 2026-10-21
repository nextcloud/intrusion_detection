<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks;

use OCA\IntrusionDetection\Check\Category;
use OCA\IntrusionDetection\Check\CheckDefinition;
use OCA\IntrusionDetection\Check\CheckTexts;
use OCA\IntrusionDetection\Check\CostClass;
use OCA\IntrusionDetection\Check\DataKind;
use OCA\IntrusionDetection\Check\ICheck;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Check\Severity;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Explain\DetectionFacts;
use OCA\IntrusionDetection\Explain\IAsksWasThisYou;
use OCA\IntrusionDetection\Explain\IExplainsDetection;
use OCA\IntrusionDetection\Explain\IExplainsToUser;
use OCA\IntrusionDetection\Explain\UserNotice;
use OCP\IL10N;

/**
 * An app or script logged in with the account's real password (Basic auth)
 * while that needed extra confirmation, which an app cannot give, so the
 * request was refused (concept section 11.5). One detection per account,
 * address and day; the user is told at most once a day. Raised by the
 * step-up service.
 */
final class StepUpRefusedClient implements ICheck, IExplainsDetection, IExplainsToUser, IAsksWasThisYou {
	public const ID = 'step_up_refused_client';

	public function __construct(
		private readonly DateFormatter $dates,
	) {
	}

	#[\Override]
	public function definition(): CheckDefinition {
		return new CheckDefinition(
			id: self::ID,
			category: Category::Internal,
			defaultMode: Mode::Protect,
			severity: Severity::Low,
			params: [],
			responses: [ResponseType::NotifyAdmin, ResponseType::NotifyUser],
			defaultResponses: [ResponseType::NotifyUser],
			cost: CostClass::OnLoginOnly,
			stores: [DataKind::Detections],
			texts: static fn (IL10N $l): CheckTexts => new CheckTexts(
				name: $l->t('App login with the password refused'),
				summary: $l->t('An app or script logged in with the account\'s password while logins with it needed extra confirmation.'),
				detects: $l->t('Apps that send the account\'s real password with every request, instead of an app password, cannot answer a request for extra confirmation. While a login with the password needs one, for example because the address took part in an attack, such requests are refused whenever the account could confirm the login in a browser: with an email code, a second factor, an administrator\'s approval or a remembered device. When someone is guessing the password, the password is on a breach list or the address belongs to a hosting network, apps keep working from a familiar place (a remembered device, a trusted network, or a network the account logged in from before), and the setting for the reason decides, as it does for accounts with no way to confirm.'),
				decides: $l->t('Records the refused requests of one account from one address per day. The user is told at most once a day.'),
				wrong: $l->t('A calendar or file sync app that was set up with the password instead of an app password, used from a new place. It works again when the reason ends, or when it is connected with an app password.'),
				data: $l->t('Detections: the account, the address and the reasons, one per account, address and day.'),
			),
			internal: true,
		);
	}

	#[\Override]
	public function asksWasThisYou(Detection $detection): bool {
		return true;
	}

	#[\Override]
	public function narrative(Detection $detection, IL10N $l): array {
		$facts = DetectionFacts::of($detection);
		$sentences = [
			$l->t('At %1$s an app or script logged in as %2$s from %3$s with the account\'s password. Logins with the password needed extra confirmation, because %4$s, and apps cannot give one, so the request was refused.', [
				$this->dates->dateTime($facts->first),
				(string)$detection->getUid(),
				(string)$detection->getIp(),
				StepUpPolicy::describeAll($facts->list('policies'), $l),
			]),
		];
		if ($facts->bool('inBrowser')) {
			$sentences[] = $l->t('The account could confirm such a login in a browser, so apps must use an app password.');
		}
		if ($detection->getHits() > 1) {
			$sentences[] = $l->n('%n request was refused that day.', '%n requests were refused that day.', $detection->getHits());
		}
		return $sentences;
	}

	#[\Override]
	public function userNotice(Detection $detection, IL10N $l): UserNotice {
		$facts = DetectionFacts::of($detection);
		return new UserNotice(
			$l->t('An app could not log in with your password'),
			[
				$l->t('An app or script logged in to your account with your password, not with an app password. Logins with your password need extra confirmation right now, because %s. Apps cannot give it, so the app was refused.', [StepUpPolicy::describeAll($facts->list('policies'), $l)]),
			],
			[
				$l->t('If this was one of your apps, connect it with an app password from your security settings instead of your password.'),
				$l->t('If it was not you, someone knows your password: change it, and answer "No, it was not me".'),
			],
		);
	}
}
