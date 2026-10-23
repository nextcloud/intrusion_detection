<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Personal;

use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Confirm\SecondFactors;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Notification\MailReach;
use OCA\IntrusionDetection\Notification\UserMessages;
use OCA\IntrusionDetection\Response\AccountProtection;
use OCA\IntrusionDetection\Response\PasswordChangeFlag;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCA\IntrusionDetection\WasThisYou\PersonalDetections;
use OCA\IntrusionDetection\WasThisYou\Questions;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IDateTimeFormatter;
use OCP\IL10N;
use OCP\IURLGenerator;
use OCP\IUser;

/**
 * The top of the user's security section (concept section 15.1): one status
 * line in plain words, the failed logins of the last 30 days, and the hint
 * for accounts that Nextcloud has no way to confirm.
 *
 * The status names what needs the user now, most important first: open
 * "Was this you?" questions, a required new password, extra protection of
 * the account, recent events, failed logins. It never names thresholds,
 * other accounts or administrator notes.
 *
 * @psalm-import-type IntrusionDetectionPersonalOverview from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionPersonalStatus from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionPersonalStatusItem from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionEmailHint from ResponseDefinitions
 */
class PersonalOverview {
	public const RECENT_DAYS = 30;
	public function __construct(
		private readonly FailedLoginStats $failedLogins,
		private readonly DetectionMapper $detections,
		private readonly Questions $questions,
		private readonly PasswordChangeFlag $passwordChange,
		private readonly AccountProtection $protection,
		private readonly SecondFactors $secondFactors,
		private readonly MailReach $reach,
		private readonly UserMessages $messages,
		private readonly AppSettings $settings,
		private readonly IDateTimeFormatter $formatter,
		private readonly IURLGenerator $urlGenerator,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * @return IntrusionDetectionPersonalOverview
	 */
	public function get(IUser $user, IL10N $l): array {
		$timeZone = $this->messages->timeZoneOf($user);
		$failedLogins = $this->failedLogins->forUser($user->getUID(), $timeZone);
		return [
			'status' => $this->status($user, $l, $timeZone, $failedLogins['total']),
			'failedLogins' => $failedLogins,
			'emailHint' => $this->emailHint($user),
			'timezone' => $timeZone->getName(),
		];
	}

	/**
	 * @return IntrusionDetectionPersonalStatus
	 */
	public function status(IUser $user, IL10N $l, \DateTimeZone $timeZone, int $failedLogins): array {
		$uid = $user->getUID();
		$now = $this->timeFactory->getTime();
		$since = $now - $this->settings->retentionDays() * 86400;
		$open = 0;
		$recent = 0;
		foreach ($this->messages->toldToUser($this->detections->findList(new DetectionFilter(uid: $uid, since: $since, limit: PersonalDetections::MAX))) as $detection) {
			if ($this->questions->isOpen($detection)) {
				$open++;
			}
			if ($detection->getCreatedTime() >= $now - self::RECENT_DAYS * 86400) {
				$recent++;
			}
		}

		/** @var list<IntrusionDetectionPersonalStatusItem> $items */
		$items = [];
		if ($open > 0) {
			$items[] = self::item('questions', 'warning', $l->n(
				'One event needs your answer: was this you?',
				'%n events need your answer: was this you?',
				$open,
			));
		}
		if ($this->passwordChange->isRequired($uid)) {
			$items[] = self::item('password_change', 'warning', $l->t('You will be asked to choose a new password the next time you log in.'));
		}
		$protectedUntil = $this->protection->protectedUntil($uid);
		if ($protectedUntil !== null) {
			$items[] = self::item('protected', 'warning', $l->t(
				'Your account is under extra protection until %s because someone is trying to guess your password. Until then, logins with your password need an extra confirmation.',
				[$this->until($protectedUntil, $now, $timeZone, $l)],
			), $protectedUntil);
		}
		if ($recent > 0) {
			$items[] = self::item('events', 'info', $l->n(
				'%n security event in the last 30 days. What happened and what Nextcloud did is listed below.',
				'%n security events in the last 30 days. What happened and what Nextcloud did is listed below.',
				$recent,
			));
		}
		if ($failedLogins > 0) {
			$items[] = self::item('failed_logins', 'info', $l->n(
				'%n failed login in the last 30 days.',
				'%n failed logins in the last 30 days.',
				$failedLogins,
			));
		}

		$level = 'ok';
		foreach ($items as $item) {
			if ($item['level'] === 'warning') {
				$level = 'warning';
				break;
			}
			if ($item['id'] === 'events') {
				$level = 'info';
			}
		}
		if ($level === 'ok') {
			return ['level' => 'ok', 'headline' => $l->t('No unusual activity in the last 30 days'), 'items' => $items];
		}
		return ['level' => $level, 'headline' => $items[0]['text'], 'items' => array_slice($items, 1)];
	}

	/**
	 * Where to add an email address and set up a second factor, for an
	 * account that has neither; null when it has one of them.
	 *
	 * @return ?IntrusionDetectionEmailHint
	 */
	public function emailHint(IUser $user): ?array {
		if ($this->reach->hasAddress($user) || $this->secondFactors->has($user)) {
			return null;
		}
		return [
			'emailUrl' => $this->urlGenerator->linkToRoute('settings.PersonalSettings.index', ['section' => 'profile-contact']),
			'secondFactorUrl' => $this->secondFactors->available($user, settable: true)
				? $this->urlGenerator->linkToRoute('settings.PersonalSettings.index', ['section' => 'security']) . '#two-factor-auth'
				: null,
		];
	}

	private function until(int $until, int $now, \DateTimeZone $timeZone, IL10N $l): string {
		$sameDay = (new \DateTimeImmutable('@' . $until))->setTimezone($timeZone)->format('Y-m-d')
			=== (new \DateTimeImmutable('@' . $now))->setTimezone($timeZone)->format('Y-m-d');
		return $sameDay
			? $this->formatter->formatTime($until, 'short', $timeZone, $l)
			: $this->formatter->formatDateTime($until, 'long', 'short', $timeZone, $l);
	}

	/**
	 * @param 'info'|'warning' $level
	 * @return IntrusionDetectionPersonalStatusItem
	 */
	private static function item(string $id, string $level, string $text, ?int $at = null): array {
		return ['id' => $id, 'level' => $level, 'text' => $text, 'at' => $at];
	}
}
