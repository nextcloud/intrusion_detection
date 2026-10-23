<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Takeover\Signals;

use OCA\IntrusionDetection\Check\Checks\RiskyNetwork\RiskyNetwork;
use OCA\IntrusionDetection\Check\Checks\RiskyNetwork\RiskyNetworkDetector;
use OCA\IntrusionDetection\Confirm\LoginDetections;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Detection\CommonFacts;
use OCA\IntrusionDetection\Explain\DetectionFacts;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\Takeover\IRiskyLoginSignal;
use OCA\IntrusionDetection\Takeover\RiskyLogin;
use OCP\AppFramework\Utility\ITimeFactory;

/**
 * The session's login came from a hosting provider or a Tor exit node:
 * a `risky_network` detection of the account is linked to the session
 * ({@see LoginDetections}). The risky login starts when the session
 * logged in, as the login history says, or else when the detection was
 * last seen.
 */
class RiskyNetworkSignal implements IRiskyLoginSignal {
	/** At most this many of the account's recent detections are looked at */
	private const LIMIT = 10;

	public function __construct(
		private readonly DetectionMapper $detections,
		private readonly LoginHistory $history,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	#[\Override]
	public function riskyLogin(string $uid, ?int $sessionTokenId): ?RiskyLogin {
		if ($sessionTokenId === null) {
			return null;
		}
		$since = $this->timeFactory->getTime() - 2 * RiskyNetworkDetector::MERGE_WINDOW;
		$found = $this->detections->findList(new DetectionFilter(checkIds: [RiskyNetwork::ID], uid: $uid, since: $since, limit: self::LIMIT));
		foreach ($found as $detection) {
			$sessions = CommonFacts::fromArray(DetectionFacts::of($detection)->facts)->sessionTokenIds ?? [];
			if (in_array($sessionTokenId, $sessions, true)) {
				$at = $this->history->forSession($uid, $sessionTokenId)?->createdAt ?? $detection->getLastSeenAt();
				return new RiskyLogin($at, RiskyLogin::REASON_RISKY_NETWORK);
			}
		}
		return null;
	}
}
