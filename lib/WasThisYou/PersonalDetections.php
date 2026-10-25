<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\WasThisYou;

use OCA\IntrusionDetection\Check\Checks\UserDenied\UserDenied;
use OCA\IntrusionDetection\Check\Checks\UserDenied\UserDeniedFacts;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Explain\DetectionFacts;
use OCA\IntrusionDetection\Explain\TextRenderer;
use OCA\IntrusionDetection\LoginHistory\SignInHabits;
use OCA\IntrusionDetection\Notification\UserMessages;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IUser;

/**
 * A user's own detections as the user sees them: what happened, when and
 * from where, what Nextcloud did and what to do, in the words of the
 * check's user notice ({@see UserMessages}), and whether it asks "Was this
 * you?". An open question is put next to the account's habit when the
 * caller has it ({@see SignInComparison}). Never thresholds, other accounts
 * or administrator notes.
 *
 * @psalm-import-type IntrusionDetectionPersonalDetection from ResponseDefinitions
 */
class PersonalDetections {
	public const MAX = 100;
	/** The answer's own detection is looked for this many seconds before the answer */
	private const RECEIPT_SLACK = 60;

	public function __construct(
		private readonly DetectionMapper $detections,
		private readonly UserMessages $messages,
		private readonly Questions $questions,
		private readonly WasThisYouService $answers,
		private readonly AppSettings $settings,
		private readonly ITimeFactory $timeFactory,
		private readonly SignInComparison $comparison,
	) {
	}

	/**
	 * @return list<IntrusionDetectionPersonalDetection> newest first
	 */
	public function forUser(IUser $user, int $limit = 50): array {
		$since = $this->timeFactory->getTime() - $this->settings->retentionDays() * 86400;
		return array_map(fn (Detection $d): array => $this->present($d, $user), $this->find($user, $since, max(1, min(self::MAX, $limit))));
	}

	/**
	 * The user's detections since a time that they are told about
	 * ({@see UserMessages::tellsUser()}): of the newest `$limit`, those.
	 *
	 * @return list<Detection> newest first
	 */
	public function find(IUser $user, int $since, int $limit): array {
		return $this->messages->toldToUser($this->detections->findList(new DetectionFilter(uid: $user->getUID(), since: $since, limit: $limit)));
	}

	/**
	 * @param ?SignInHabits $habits the account's habits, to compare an open question with
	 * @return IntrusionDetectionPersonalDetection
	 */
	public function present(Detection $detection, IUser $user, ?SignInHabits $habits = null): array {
		$message = $this->messages->build($detection, $user, onSecurityPage: true);
		$asks = $this->questions->asks($detection);
		$open = $asks && $detection->getUserVerdict() === null;
		return [
			'id' => (string)$detection->getId(),
			'check' => $detection->getCheckId(),
			'severity' => $detection->getSeverity(),
			'enforced' => $detection->isEnforced(),
			'createdAt' => $detection->getCreatedTime(),
			'lastSeenAt' => $detection->getLastSeenAt(),
			'hits' => $detection->getHits(),
			'subject' => $message->subject,
			'happened' => $message->happened,
			'when' => $message->when,
			'done' => $message->done,
			'advice' => $message->advice,
			'address' => $detection->getIp(),
			'asks' => $asks,
			'verdict' => $detection->getUserVerdict(),
			'verdictAt' => $detection->getVerdictAt(),
			'canConfirm' => $open && $this->answers->maySessionVouch($detection),
			'comparison' => $open && $habits !== null ? $this->comparison->describe($detection, $user, $habits) : null,
			'receipt' => null,
		];
	}

	/**
	 * What Nextcloud did after the user answered "No, it was not me" about
	 * a detection: the responses its answer's own detection
	 * ({@see UserDenied}) recorded as done, and the network whose logins
	 * need extra confirmation now. Only what happened; empty when nothing
	 * acted, null when the detection was not answered "No".
	 *
	 * @return ?list<string>
	 */
	public function receipt(Detection $answered, IUser $user): ?array {
		if ($answered->getUserVerdict() !== Detection::VERDICT_DENIED) {
			return null;
		}
		$since = ($answered->getVerdictAt() ?? $this->timeFactory->getTime()) - self::RECEIPT_SLACK;
		$denials = $this->detections->findList(new DetectionFilter(checkIds: [UserDenied::ID], uid: $user->getUID(), since: $since, limit: 10));
		foreach ($denials as $denial) {
			$facts = UserDeniedFacts::fromArray(DetectionFacts::of($denial)->facts);
			if ($facts->detection !== (string)$answered->getId()) {
				continue;
			}
			$done = $this->messages->build($denial, $user, onSecurityPage: true)->done;
			if (($facts->network ?? '') !== '' && $denial->isEnforced()) {
				$l = $this->messages->l10nFor($user);
				$done[] = $l->t('Logins from that network need extra confirmation for %s.', [TextRenderer::duration(FlaggedSources::DURATION, $l)]);
			}
			return $done;
		}
		return [];
	}
}
