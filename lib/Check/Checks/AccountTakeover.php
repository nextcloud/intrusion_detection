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
use OCA\IntrusionDetection\Check\ParamDefinition;
use OCA\IntrusionDetection\Check\ParamText;
use OCA\IntrusionDetection\Check\ParamType;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Check\Severity;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Explain\DetectionFacts;
use OCA\IntrusionDetection\Explain\IAsksWasThisYou;
use OCA\IntrusionDetection\Explain\IExplainsDetection;
use OCA\IntrusionDetection\Explain\IExplainsToUser;
use OCA\IntrusionDetection\Explain\TextRenderer;
use OCA\IntrusionDetection\Explain\UserNotice;
use OCA\IntrusionDetection\Takeover\SecurityChangeType;
use OCP\IL10N;

/**
 * Several security changes to one account shortly after a risky login, or
 * many from any session (concept section 10.14): the pattern of someone who
 * got in and now locks the owner out. The detector is
 * {@see AccountTakeoverDetector}; the changes come from the security change
 * log.
 */
final class AccountTakeover implements ICheck, IExplainsDetection, IExplainsToUser, IAsksWasThisYou {
	public const ID = 'account_takeover';

	public const PARAM_WINDOW = 'window';
	public const PARAM_MIN_POINTS = 'min_points';
	public const PARAM_WINDOW_ANY = 'window_any';
	public const PARAM_MIN_POINTS_ANY = 'min_points_any';

	/** Why a detection fired, as stored in its facts */
	public const RULE_RISKY_LOGIN = 'risky_login';
	public const RULE_ANY_SESSION = 'any_session';

	/** @var array<string, int> default points per kind of change */
	public const DEFAULT_POINTS = [
		'email_changed' => 2,
		'password_changed' => 1,
		'second_factor_added' => 1,
		'second_factor_removed' => 3,
		'second_factor_disabled' => 3,
		'app_password_created' => 1,
		'device_connected' => 1,
	];

	public function __construct(
		private readonly DateFormatter $dates,
	) {
	}

	#[\Override]
	public function definition(): CheckDefinition {
		$params = [
			new ParamDefinition(self::PARAM_WINDOW, ParamType::Duration, 3600, min: 600, max: 86400),
			new ParamDefinition(self::PARAM_MIN_POINTS, ParamType::Int, 3, min: 1, max: 50),
			new ParamDefinition(self::PARAM_WINDOW_ANY, ParamType::Duration, 1800, min: 600, max: 86400),
			new ParamDefinition(self::PARAM_MIN_POINTS_ANY, ParamType::Int, 5, min: 1, max: 50),
		];
		foreach (self::DEFAULT_POINTS as $type => $points) {
			$params[] = new ParamDefinition('points_' . $type, ParamType::Int, $points, min: 0, max: 10);
		}
		return new CheckDefinition(
			id: self::ID,
			category: Category::DevicesAndSessions,
			defaultMode: Mode::Protect,
			severity: Severity::High,
			params: $params,
			responses: [
				ResponseType::KillSession,
				ResponseType::LockLink,
				ResponseType::NotifyAdmin,
				ResponseType::NotifyUser,
			],
			defaultResponses: [
				ResponseType::LockLink,
				ResponseType::NotifyAdmin,
				ResponseType::NotifyUser,
			],
			cost: CostClass::OnSecurityChange,
			stores: [DataKind::SecurityChanges, DataKind::Detections, DataKind::LockLinks, DataKind::SecureAccountProgress],
			texts: static function (IL10N $l): CheckTexts {
				$points = [];
				foreach (SecurityChangeType::cases() as $type) {
					$param = $type->pointsParam();
					if ($param !== null) {
						$points[$param] = new ParamText($l->t('Points: %s', [$type->label($l)]), $l->t('How much this change counts. 0 leaves it out.'), $l->t('points'));
					}
				}
				return new CheckTexts(
					name: $l->t('Account takeover sequence'),
					summary: $l->t('Several security changes to one account shortly after a risky login.'),
					detects: $l->t('Someone who got into an account, with a stolen password or session, often makes it their own quickly: they change the email address, turn off the second factor and create an app password, so that the owner cannot get back in or notice. Each of these changes is normal on its own; several of them close together are not.'),
					decides: $l->t('Every change counts points: email address {points_email_changed}, password {points_password_changed}, second factor added {points_second_factor_added}, removed {points_second_factor_removed}, turned off {points_second_factor_disabled}, app password {points_app_password_created}, device connected {points_device_connected}. Fires when the changes made in one session within {window} after a risky login add up to {min_points} points, or when the changes from any session within {window_any} add up to {min_points_any}. A login is risky when it needed extra confirmation and was let in without one. Changes made by an administrator, with occ, or by a password reset through email never count.'),
					wrong: $l->t('A user who sets up their account on a new phone right after logging in from a hotel network: a new app password, a second factor and a new email address. They are asked "Was this you?" and can answer yes. Raise the points needed if this happens often.'),
					data: $l->t('Security changes: the kind of change, the address, the session and the time, kept {history_retention_days} days. Email addresses only masked, like f***@example.com; the full previous address is kept encrypted for one day, so that the lock link can reach it. Lock links: a keyed fingerprint of the link, never the link itself, deleted after 7 days.'),
					params: array_merge([
						self::PARAM_WINDOW => new ParamText($l->t('After a risky login, within'), $l->t('Changes made in the session of a risky login count when they are made within this time after the login.')),
						self::PARAM_MIN_POINTS => new ParamText($l->t('Points after a risky login'), $l->t('Fires when the changes of that session reach this many points.'), $l->t('points')),
						self::PARAM_WINDOW_ANY => new ParamText($l->t('From any session, within'), $l->t('Changes from any session of the account count when they are made within this time.')),
						self::PARAM_MIN_POINTS_ANY => new ParamText($l->t('Points from any session'), $l->t('Fires when the changes of the account reach this many points, however the login looked.'), $l->t('points')),
					], $points),
				);
			},
		);
	}

	#[\Override]
	public function asksWasThisYou(Detection $detection): bool {
		return true;
	}

	#[\Override]
	public function narrative(Detection $detection, IL10N $l): array {
		$facts = DetectionFacts::of($detection);
		$uid = (string)$detection->getUid();
		$sentences = [$l->t('These security changes were made to the account %s:', [$uid])];
		foreach (self::changes($facts) as $change) {
			$sentences[] = $this->changeSentence($change, $l);
		}
		$rules = $facts->list('rules');
		if (in_array(self::RULE_RISKY_LOGIN, $rules, true)) {
			$sentences[] = $l->t('The session they were made in started with a risky login at %s: it needed extra confirmation and was let in without one.', [$this->dates->dateTime($facts->int('riskyLoginAt'))]);
			$sentences[] = $l->t('Together they count %1$s points. The limit at that time was %2$s points within %3$s after a risky login.', [
				(string)$facts->int('sessionPoints'),
				(string)$facts->threshold(self::PARAM_MIN_POINTS, 3),
				TextRenderer::duration($facts->threshold(self::PARAM_WINDOW, 3600), $l),
			]);
		}
		if (in_array(self::RULE_ANY_SESSION, $rules, true)) {
			$sentences[] = $l->t('The changes from all sessions count %1$s points. The limit at that time was %2$s points within %3$s.', [
				(string)$facts->int('anyPoints'),
				(string)$facts->threshold(self::PARAM_MIN_POINTS_ANY, 5),
				TextRenderer::duration($facts->threshold(self::PARAM_WINDOW_ANY, 1800), $l),
			]);
		}
		if ($facts->has('userHasEmail') && !$facts->bool('userHasEmail')) {
			$sentences[] = $l->t('The account has no email address now. You may be the only one who can reach its owner outside the account, which may be in someone else\'s hands.');
		}
		return $sentences;
	}

	#[\Override]
	public function userNotice(Detection $detection, IL10N $l): UserNotice {
		$facts = DetectionFacts::of($detection);
		$labels = [];
		foreach (self::changes($facts) as $change) {
			$type = SecurityChangeType::tryFrom((string)($change['type'] ?? ''));
			if ($type !== null) {
				$labels[$type->value] = $type->label($l);
			}
		}
		return new UserNotice(
			$l->t('Important changes to your account'),
			[
				$labels === []
					? $l->t('Several security settings of your account were changed within a short time.')
					: $l->t('Several security settings of your account were changed within a short time: %s.', [implode(', ', $labels)]),
				$l->t('If you made these changes, there is nothing to do.'),
				$l->t('If you did not, someone else may be using your account.'),
			],
			[
				$l->t('If it was not you, answer "No, it was not me". Nextcloud then ends the sessions involved and guides you through securing your account.'),
				$l->t('Check your email address, your second factor and your devices in your security settings.'),
			],
		);
	}

	/**
	 * @return list<array<array-key, mixed>>
	 */
	private static function changes(DetectionFacts $facts): array {
		$changes = $facts->value('changes');
		return is_array($changes) ? array_values(array_filter($changes, 'is_array')) : [];
	}

	/**
	 * @param array<array-key, mixed> $change
	 */
	private function changeSentence(array $change, IL10N $l): string {
		$type = SecurityChangeType::tryFrom((string)($change['type'] ?? ''));
		$label = $type?->label($l) ?? $l->t('Security change');
		$old = is_string($change['old'] ?? null) ? $change['old'] : null;
		$new = is_string($change['new'] ?? null) ? $change['new'] : null;
		if ($type === SecurityChangeType::EmailChanged) {
			$label = match (true) {
				$old !== null && $new !== null => $l->t('Email address changed from %1$s to %2$s', [$old, $new]),
				$old !== null => $l->t('Email address %s removed', [$old]),
				$new !== null => $l->t('Email address %s added', [$new]),
				default => $label,
			};
		}
		$at = $this->dates->dateTime((int)($change['at'] ?? 0));
		$ip = is_string($change['ip'] ?? null) ? $change['ip'] : null;
		$points = (int)($change['points'] ?? 0);
		return $ip === null
			? $l->n('%1$s, at %2$s (%n point).', '%1$s, at %2$s (%n points).', $points, [$label, $at])
			: $l->n('%1$s, at %2$s from %3$s (%n point).', '%1$s, at %2$s from %3$s (%n points).', $points, [$label, $at, $ip]);
	}
}
