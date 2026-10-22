<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Personal;

use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Confirm\Methods\AdminApprovalMethod;
use OCA\IntrusionDetection\Confirm\StepUpService;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Guide\SecureAccountOverview;
use OCA\IntrusionDetection\KnownDevice\DeviceLabel;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\LoginHistory\LoginHistoryEntry;
use OCA\IntrusionDetection\Notification\UserMessages;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCA\IntrusionDetection\SessionState\CurrentSession;
use OCA\IntrusionDetection\Takeover\Db\SecurityChangeMapper;
use OCA\IntrusionDetection\WasThisYou\PersonalDetections;
use OCA\IntrusionDetection\WasThisYou\Questions;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IL10N;
use OCP\IUser;

/**
 * The user's own recent activity on the security page (concept section
 * 15.1): the open "Was this you?" questions, and one timeline, newest
 * first, of their logins, security changes, days with failed logins and
 * the other security events, answered questions among them.
 *
 * Each source costs one query by its (uid, created_at) index, or the
 * unique (uid, day) index of the daily failure counts, and reads at most
 * one row more than shown; the open questions are a second query of the
 * unanswered detections of the checks that ask, of at most MAX_QUESTIONS
 * rows, repeated for up to QUESTION_PAGES pages while their rows do not
 * ask. Only events that are shown are put into words.
 *
 * @psalm-import-type IntrusionDetectionPersonalActivity from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionPersonalActivityItem from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionLogin from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionSecurityChange from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionFailedLoginActivity from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionPersonalDetection from ResponseDefinitions
 */
class PersonalActivity {
	public const MAX_LIMIT = 100;
	/** Open questions listed at most */
	public const MAX_QUESTIONS = 50;
	/** Pages of MAX_QUESTIONS unanswered detections read at most for them */
	public const QUESTION_PAGES = 4;
	public const MAX_DAYS = 365;

	private const KIND_ORDER = ['event' => 0, 'change' => 1, 'login' => 2, 'failed_logins' => 3];

	public function __construct(
		private readonly DetectionMapper $detections,
		private readonly Questions $questions,
		private readonly PersonalDetections $personalDetections,
		private readonly LoginHistory $loginHistory,
		private readonly SecurityChangeMapper $changes,
		private readonly FailedLoginStats $failedLogins,
		private readonly UserMessages $messages,
		private readonly CurrentSession $currentSession,
		private readonly AppSettings $settings,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * @param int $days how far back the timeline goes
	 * @param int $limit the most timeline entries
	 * @return IntrusionDetectionPersonalActivity
	 */
	public function forUser(IUser $user, IL10N $l, int $days, int $limit): array {
		$uid = $user->getUID();
		$days = max(1, min(self::MAX_DAYS, $days));
		$limit = max(1, min(self::MAX_LIMIT, $limit));
		$now = $this->timeFactory->getTime();
		$since = $now - $days * 86400;
		$timeZone = $this->messages->timeZoneOf($user);

		/** @var list<array{at: int, kind: 'login'|'change'|'failed_logins'|'event', id: int|string, make: \Closure(): IntrusionDetectionPersonalActivityItem}> $entries */
		$entries = [];
		$day = static fn (int $at): string => (new \DateTimeImmutable('@' . $at))->setTimezone($timeZone)->format('Y-m-d');

		// Open questions are listed however old they are, newest first; the rest by the timeline's window.
		$questions = [];
		$askingChecks = $this->questions->askingCheckIds();
		$retained = $now - $this->settings->retentionDays() * 86400;
		for ($page = 0; $page < self::QUESTION_PAGES && count($questions) < self::MAX_QUESTIONS; $page++) {
			// Some checks ask for some of their detections only: those are read past, a page at a time.
			$unanswered = $this->detections->findList(new DetectionFilter(
				checkIds: $askingChecks,
				uid: $uid,
				since: $retained,
				limit: self::MAX_QUESTIONS,
				offset: $page * self::MAX_QUESTIONS,
				answered: false,
			));
			foreach ($unanswered as $detection) {
				if (count($questions) < self::MAX_QUESTIONS && $this->questions->isOpen($detection) && $this->messages->tellsUser($detection)) {
					$questions[] = $this->personalDetections->present($detection, $user);
				}
			}
			if (count($unanswered) < self::MAX_QUESTIONS) {
				break;
			}
		}
		$found = $this->detections->findList(new DetectionFilter(uid: $uid, since: $since, limit: PersonalDetections::MAX));
		$events = 0;
		foreach ($found as $detection) {
			if ($this->questions->isOpen($detection) || !$this->messages->tellsUser($detection)) {
				continue;
			}
			if ($events > $limit) {
				continue;
			}
			$events++;
			$entries[] = [
				'at' => $detection->getCreatedAt(),
				'kind' => 'event',
				'id' => $detection->getId(),
				'make' => fn (): array => self::item('event-' . $detection->getId(), 'event', $detection->getCreatedAt(), $day($detection->getCreatedAt()), event: $this->personalDetections->present($detection, $user)),
			];
		}
		// Older events than the oldest one read may exist.
		$moreEvents = count($found) >= PersonalDetections::MAX;

		$current = $this->currentSession->tokenId();
		$waitedOutBefore = $this->waitedOutBefore();
		foreach ($this->loginHistory->forUser($uid, $since, null, $limit + 1) as $entry) {
			$entries[] = [
				'at' => $entry->createdAt,
				'kind' => 'login',
				'id' => $entry->id,
				'make' => static fn (): array => self::item('login-' . $entry->id, 'login', $entry->createdAt, $day($entry->createdAt), login: self::login($entry, $current, $waitedOutBefore, $l)),
			];
		}

		foreach ($this->changes->findRecent($uid, $since, $limit + 1) as $row) {
			$entries[] = [
				'at' => $row['created_at'],
				'kind' => 'change',
				'id' => $row['id'],
				'make' => static fn (): array => self::item('change-' . $row['id'], 'change', $row['created_at'], $day($row['created_at']), change: SecureAccountOverview::change($row, $l)),
			];
		}

		foreach ($this->failedLogins->daysWithFailures($uid, $timeZone) as $failed) {
			if ($failed['lastAt'] < $since) {
				continue;
			}
			$entries[] = [
				'at' => $failed['lastAt'],
				'kind' => 'failed_logins',
				'id' => $failed['day'],
				'make' => static fn (): array => self::item('failed-' . $failed['day'], 'failed_logins', $failed['lastAt'], $failed['day'], failedLogins: ['count' => $failed['count']]),
			];
		}

		usort($entries, static fn (array $a, array $b): int => $b['at'] <=> $a['at']
			?: self::KIND_ORDER[$a['kind']] <=> self::KIND_ORDER[$b['kind']]
			?: $b['id'] <=> $a['id']);

		$items = array_map(static fn (array $entry): array => ($entry['make'])(), array_slice($entries, 0, $limit));
		return [
			'questions' => $questions,
			'items' => $items,
			'hasMore' => count($entries) > $limit || $moreEvents,
			'today' => $day($now),
			'timezone' => $timeZone->getName(),
		];
	}

	/**
	 * @param 'login'|'change'|'failed_logins'|'event' $kind
	 * @param ?IntrusionDetectionLogin $login
	 * @param ?IntrusionDetectionSecurityChange $change
	 * @param ?IntrusionDetectionFailedLoginActivity $failedLogins
	 * @param ?IntrusionDetectionPersonalDetection $event
	 * @return IntrusionDetectionPersonalActivityItem
	 */
	private static function item(string $id, string $kind, int $at, string $day, ?array $login = null, ?array $change = null, ?array $failedLogins = null, ?array $event = null): array {
		return ['id' => $id, 'kind' => $kind, 'at' => $at, 'day' => $day, 'login' => $login, 'change' => $change, 'failedLogins' => $failedLogins, 'event' => $event];
	}

	/**
	 * Logins that still wait for a confirmation and started before this
	 * time can no longer be confirmed: they waited longer than a login
	 * session, and an administrator's approval when those are on, last.
	 */
	public function waitedOutBefore(): int {
		$approval = $this->settings->stepUpAdminApproval() ? AdminApprovalMethod::TTL : 0;
		return $this->timeFactory->getTime() - StepUpService::SESSION_TTL - $approval;
	}

	/**
	 * One login as the user sees it. A login that waited out its
	 * confirmation is shown as failed, as the background job records it.
	 *
	 * @param ?int $current the token id of the current session
	 * @param int $waitedOutBefore see {@see waitedOutBefore()}
	 * @return IntrusionDetectionLogin
	 */
	public static function login(LoginHistoryEntry $entry, ?int $current, int $waitedOutBefore, IL10N $l): array {
		[$family, $platform] = DeviceLabel::parse($entry->userAgent);
		return [
			'id' => $entry->id,
			'createdAt' => $entry->createdAt,
			'ip' => $entry->ip,
			'network' => $entry->netKey,
			'userAgent' => $entry->userAgent,
			'method' => $entry->method,
			'knownDevice' => $entry->knownDevice,
			'confirmedBy' => $entry->confirmedBy,
			'stepUp' => $entry->stepUp === LoginHistory::STEP_UP_PENDING && $entry->createdAt < $waitedOutBefore ? LoginHistory::STEP_UP_FAILED : $entry->stepUp,
			'current' => $current !== null && $entry->sessionTokenId === $current,
			'device' => DeviceLabel::translated($family, $platform, $l),
		];
	}
}
