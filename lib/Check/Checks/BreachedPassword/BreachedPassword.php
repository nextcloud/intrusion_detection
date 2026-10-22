<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\BreachedPassword;

use OCA\IntrusionDetection\Check\ICheck;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Definition\Category;
use OCA\IntrusionDetection\Definition\CheckDefinition;
use OCA\IntrusionDetection\Definition\CheckTexts;
use OCA\IntrusionDetection\Definition\CostClass;
use OCA\IntrusionDetection\Definition\DataKind;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\ParamDefinition;
use OCA\IntrusionDetection\Definition\ParamText;
use OCA\IntrusionDetection\Definition\ParamType;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Definition\Severity;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Explain\DetectionFacts;
use OCA\IntrusionDetection\Explain\IExplainsDetection;
use OCA\IntrusionDetection\Explain\IExplainsToUser;
use OCA\IntrusionDetection\Explain\UserNotice;
use OCP\IL10N;

/**
 * A password that appears in public lists of leaked passwords, checked at an
 * interactive login. Off by default, because it contacts an external
 * service. The detector is {@see BreachedPasswordDetector}.
 */
final class BreachedPassword implements ICheck, IExplainsDetection, IExplainsToUser {
	public const ID = 'breached_password';

	public function __construct(
		private readonly DateFormatter $dates,
	) {
	}

	#[\Override]
	public function definition(): CheckDefinition {
		return new CheckDefinition(
			id: self::ID,
			category: Category::LoginAttacks,
			defaultMode: Mode::Off,
			severity: Severity::Medium,
			params: [
				new ParamDefinition('recheck_days', ParamType::Int, 30, min: 7, max: 365),
				new ParamDefinition('min_count', ParamType::Int, 1, min: 1, max: 1000000),
			],
			responses: [ResponseType::ForcePasswordChange, ResponseType::StepUp, ResponseType::NotifyAdmin, ResponseType::NotifyUser],
			defaultResponses: [ResponseType::ForcePasswordChange, ResponseType::StepUp, ResponseType::NotifyUser],
			cost: CostClass::ExternalCall,
			stores: [DataKind::AccountState, DataKind::Detections],
			texts: static fn (IL10N $l): CheckTexts => new CheckTexts(
				name: $l->t('Password known from data breaches'),
				shortName: $l->t('Breached password'),
				summary: $l->t('A user logs in with a password that appears in public lists of leaked passwords.'),
				detects: $l->t('Passwords stolen from other websites are published in long lists, and attackers try the passwords on these lists first. A password on such a list is weak, however long it looks, even if it never leaked from your server. Nextcloud checks the password against the Pwned Passwords list of the Have I Been Pwned service when the user logs in, without revealing it.'),
				decides: $l->t('Checks the password at a login through the login form, when it was not checked in the last {recheck_days} days, and at the first such login after the password changed. Fires when the password is on the list with a count of at least {min_count}. Apps and devices that log in with an app password are never checked.'),
				wrong: $l->t('A password can be on the list because someone else chose the same one, not because this account leaked. It should still be changed, because attackers try these passwords first. If the service cannot be reached, nothing happens and the password is checked at the next login.'),
				data: $l->t('Per account: when the password was last checked, and whether it was found. Nothing about the password itself is stored. What leaves the server: the first 5 characters of the SHA-1 hash of the password, for example 21BD1, sent to api.pwnedpasswords.com. The full password and its full hash never leave the server. The service answers with all known hashes that start with these 5 characters, and Nextcloud compares them on the server.'),
				params: [
					'recheck_days' => new ParamText(
						$l->t('Check again after'),
						$l->t('A password that was checked is checked again after this many days. A changed password is always checked at the next login.'),
						$l->t('days'),
					),
					'min_count' => new ParamText(
						$l->t('Minimum count in the list'),
						$l->t('How often the password must appear in the list. 1 means anywhere in it.'),
					),
				],
				cost: $l->t('One request to api.pwnedpasswords.com per user every {recheck_days} days, during the login. It adds at most 1.5 seconds to that login, typically about 150 ms. Answers are kept in the memory cache for a day.'),
			),
			sendsData: true,
		);
	}

	#[\Override]
	public function narrative(Detection $detection, IL10N $l): array {
		$facts = DetectionFacts::of($detection);
		$sentences = [];
		$ip = $detection->getIp();
		$sentences[] = $ip === null || $ip === ''
			? $l->t('At %1$s the account %2$s logged in with a password that appears in the public list of leaked passwords.', [
				$this->dates->dateTime($facts->first),
				(string)$detection->getUid(),
			])
			: $l->t('At %1$s the account %2$s logged in from %3$s with a password that appears in the public list of leaked passwords.', [
				$this->dates->dateTime($facts->first),
				(string)$detection->getUid(),
				$ip,
			]);
		if ($detection->getHits() > 1) {
			$sentences[] = $l->n('It was found again %n time that day.', 'It was found again %n times that day.', $detection->getHits() - 1);
		}
		$sentences[] = $l->t('The limit at that time was a count of at least %s in the list. How often it appears is not stored, because that number could identify the password.', [
			(string)$facts->threshold('min_count', 1),
		]);
		$sentences[] = $l->t('The password was never sent anywhere: only the first 5 characters of its SHA-1 hash left the server, and the comparison happened on the server.');
		return $sentences;
	}

	#[\Override]
	public function userNotice(Detection $detection, IL10N $l): UserNotice {
		$message = [
			$l->t('The password you logged in with appears in public lists of leaked passwords.'),
			$l->t('This has nothing to do with Nextcloud: someone used the same password on another website whose data was stolen. But attackers try the passwords on these lists first.'),
		];
		$forced = false;
		foreach ($detection->getActionList() as $action) {
			if ($action['type'] === ResponseType::ForcePasswordChange->value && $action['enforced']) {
				$forced = true;
			}
		}
		$message[] = $forced
			? $l->t('You will be asked to choose a new password. Choose one that you use nowhere else.')
			: $l->t('Please change your password to one that you use nowhere else.');
		return new UserNotice($l->t('Your password appears in lists of leaked passwords'), $message);
	}
}
