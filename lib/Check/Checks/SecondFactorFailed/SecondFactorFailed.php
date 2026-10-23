<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\SecondFactorFailed;

use OCA\IntrusionDetection\Check\ICheck;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Definition\Category;
use OCA\IntrusionDetection\Definition\CheckDefinition;
use OCA\IntrusionDetection\Definition\CheckTexts;
use OCA\IntrusionDetection\Definition\CostClass;
use OCA\IntrusionDetection\Definition\DataKind;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\ParamDefinition;
use OCA\IntrusionDetection\Definition\ParamPreset;
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
 * The password was right, but the second factor failed again and again:
 * someone who knows the password is guessing the code. The detector is
 * {@see SecondFactorFailedDetector}.
 */
final class SecondFactorFailed implements ICheck, IExplainsDetection, IExplainsToUser {
	public const ID = 'second_factor_failed';

	public function __construct(
		private readonly DateFormatter $dates,
	) {
	}

	#[\Override]
	public function definition(): CheckDefinition {
		return new CheckDefinition(
			id: self::ID,
			category: Category::LoginAttacks,
			defaultMode: Mode::Protect,
			severity: Severity::High,
			params: [
				new ParamDefinition('max_failures', ParamType::Int, 3, min: 2, max: 20, preset: ParamPreset::Limit),
				new ParamDefinition('max_failures_hour', ParamType::Int, 5, min: 2, max: 100, preset: ParamPreset::Limit),
			],
			responses: [
				ResponseType::KillSession,
				ResponseType::Ban,
				ResponseType::ForcePasswordChange,
				ResponseType::FlagSource,
				ResponseType::NotifyAdmin,
				ResponseType::NotifyUser,
			],
			defaultResponses: [
				ResponseType::KillSession,
				ResponseType::Ban,
				ResponseType::ForcePasswordChange,
				ResponseType::NotifyAdmin,
				ResponseType::NotifyUser,
			],
			cost: CostClass::OnFailureOnly,
			stores: [DataKind::FailedAttempts, DataKind::Detections, DataKind::TokenOrigins],
			texts: static fn (IL10N $l): CheckTexts => new CheckTexts(
				name: $l->t('Correct password, then a failed second factor'),
				shortName: $l->t('Failed 2nd factor'),
				summary: $l->t('Someone gets the password right, but fails the second factor again and again.'),
				detects: $l->t('An attacker who has the password, from a data breach or a phishing page, but not the phone or security key of the second factor. They get past the password and then try to guess the code. Whoever does this knows the password.'),
				decides: $l->t('Fires when the second factor fails {max_failures} times in one login, or {max_failures_hour} times for one account within an hour. From an address that was flagged after an earlier attack, the first failure is enough. Backup codes count like every other second factor. One mistyped code never fires.'),
				wrong: $l->t('Someone who mistypes their code several times in a row, for example because the clock of their phone is wrong. They are logged out, must choose a new password, and their address is blocked for a while. Raise the limits, or switch blocking off for this check, if this happens to your users.'),
				data: $l->t('Failed second-factor attempts: the address, the account and the time, deleted after 1 hour. The failures of one login are counted in its session. App passwords: which session and address created them, deleted after 30 days, so that ending a session also ends the app passwords made from it.'),
			),
		);
	}

	#[\Override]
	public function narrative(Detection $detection, IL10N $l): array {
		$stored = DetectionFacts::of($detection);
		$facts = SecondFactorFailedFacts::fromArray($stored->facts);
		$sentences = [
			$l->t('%1$s entered the correct password from %2$s, but the second factor (%3$s) failed.', [
				(string)$detection->getUid(),
				(string)$detection->getIp(),
				$facts->providerName ?? $facts->provider,
			]),
			$l->n(
				'It failed %n time in that login, and %1$s times for this account within the hour.',
				'It failed %n times in that login, and %1$s times for this account within the hour.',
				$facts->loginFailures,
				[(string)$facts->hourFailures],
			),
		];
		if (in_array(SecondFactorFailedRule::Flagged, $facts->rules, true)) {
			$sentences[] = $l->t('The address had been flagged after an earlier attack, so the first failure was enough.');
		}
		if (in_array(SecondFactorFailedRule::Login, $facts->rules, true)) {
			$sentences[] = $l->t('The limit at that time was %s failures in one login.', [(string)$stored->threshold('max_failures', 3)]);
		}
		if (in_array(SecondFactorFailedRule::Hour, $facts->rules, true)) {
			$sentences[] = $l->t('The limit at that time was %s failures for one account within an hour.', [(string)$stored->threshold('max_failures_hour', 5)]);
		}
		$sentences[] = $l->t('Whoever did this knows the password of the account.');
		if ($detection->getHits() > 1) {
			$sentences[] = $l->n('It happened %n time between %1$s and %2$s.', 'It happened %n times between %1$s and %2$s.', $detection->getHits(), [
				$this->dates->dateTime($detection->getCreatedTime()),
				$this->dates->time($detection->getLastSeenAt()),
			]);
		}
		return $sentences;
	}

	#[\Override]
	public function userNotice(Detection $detection, IL10N $l): UserNotice {
		$facts = SecondFactorFailedFacts::fromArray(DetectionFacts::of($detection)->facts);
		$provider = $facts->providerName ?? $facts->provider;
		return new UserNotice(
			$l->t('Someone entered your password, but not your second factor'),
			[
				$provider !== ''
					? $l->t('Someone logged in to your account with your correct password, but could not confirm it with your second factor (%s).', [$provider])
					: $l->t('Someone logged in to your account with your correct password, but could not confirm it with your second factor.'),
				$l->t('If this was you and you mistyped your code a few times, there is no harm done.'),
				$l->t('If it was not you, someone knows your password. Your second factor stopped them.'),
			],
			[
				$l->t('Choose a new password when you are asked at your next login, and do not use it anywhere else.'),
				$l->t('If it was not you, also check your devices and sessions in your security settings.'),
			],
		);
	}
}
