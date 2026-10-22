<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\WasThisYou;

use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Notification\UserMessages;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IUser;

/**
 * A user's own detections as the user sees them: what happened, when and
 * from where, what Nextcloud did and what to do, in the words of the
 * check's user notice ({@see UserMessages}), and whether it asks "Was this
 * you?". Never thresholds, other accounts or administrator notes.
 *
 * @psalm-import-type IntrusionDetectionPersonalDetection from ResponseDefinitions
 */
class PersonalDetections {
	public const MAX = 100;

	public function __construct(
		private readonly DetectionMapper $detections,
		private readonly UserMessages $messages,
		private readonly Questions $questions,
		private readonly WasThisYouService $answers,
		private readonly AppSettings $settings,
		private readonly ITimeFactory $timeFactory,
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
	 * @return IntrusionDetectionPersonalDetection
	 */
	public function present(Detection $detection, IUser $user): array {
		$message = $this->messages->build($detection, $user, onSecurityPage: true);
		$asks = $this->questions->asks($detection);
		$open = $asks && $detection->getUserVerdict() === null;
		return [
			'id' => $detection->getId(),
			'check' => $detection->getCheckId(),
			'severity' => $detection->getSeverity(),
			'enforced' => $detection->isEnforced(),
			'createdAt' => $detection->getCreatedAt(),
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
		];
	}
}
