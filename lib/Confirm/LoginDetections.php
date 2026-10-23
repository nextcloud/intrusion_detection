<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Detection\CommonFacts;
use OCA\IntrusionDetection\Login\CoreSession;
use OCA\IntrusionDetection\Login\SessionMarkers;
use OCP\AppFramework\Db\DoesNotExistException;
use Psr\Log\LoggerInterface;

/**
 * Links detections recorded during a login to the session the login
 * created. Core creates the session token only after the login event, so
 * the detection ids wait in the session ({@see SessionMarkers::LOGIN_DETECTIONS})
 * until its first request, when the token exists. A linked detection knows
 * its session: "No, it was not me" ends it, and "Yes, it was me" is refused
 * from it.
 */
class LoginDetections {
	/** At most this many detections wait per login, and sessions are kept per detection */
	public const MAX = 10;
	/** The detection fact with the ids of the session tokens it is about */
	public const FACT = CommonFacts::SESSION_TOKEN_IDS;

	public function __construct(
		private readonly SessionMarkers $state,
		private readonly DetectionMapper $detections,
		private readonly CoreSession $coreSession,
		private readonly LoggerInterface $logger,
	) {
	}

	/**
	 * @param list<int> $ids
	 */
	public function await(string $uid, array $ids): void {
		if ($ids === []) {
			return;
		}
		$waiting = $this->state->get(SessionMarkers::LOGIN_DETECTIONS);
		$known = is_array($waiting) && ($waiting['uid'] ?? null) === $uid && is_array($waiting['ids'] ?? null) ? array_values(array_filter($waiting['ids'], 'is_int')) : [];
		$this->state->set(SessionMarkers::LOGIN_DETECTIONS, [
			'uid' => $uid,
			'ids' => array_slice(array_values(array_unique([...$known, ...$ids])), 0, self::MAX),
		]);
	}

	/**
	 * Link the waiting detections to the current session token, once.
	 *
	 * @param array<string, mixed> $waiting
	 */
	public function link(array $waiting, ?string $currentUid): void {
		$this->state->remove(SessionMarkers::LOGIN_DETECTIONS);
		$uid = $waiting['uid'] ?? null;
		$tokenId = $this->coreSession->tokenId();
		if (!is_string($uid) || $uid !== $currentUid || $tokenId === null || !is_array($waiting['ids'] ?? null)) {
			return;
		}
		foreach (array_slice($waiting['ids'], 0, self::MAX) as $id) {
			if (!is_int($id)) {
				continue;
			}
			try {
				$detection = $this->detections->findById($id);
			} catch (DoesNotExistException) {
				continue;
			}
			if ($detection->getUid() !== $uid) {
				continue;
			}
			$explanation = $detection->getExplanationData();
			$facts = is_array($explanation['facts'] ?? null) ? $explanation['facts'] : [];
			$linked = is_array($facts[self::FACT] ?? null) ? array_values(array_filter($facts[self::FACT], 'is_int')) : [];
			if (in_array($tokenId, $linked, true)) {
				continue;
			}
			// A merged detection can be about several logins: the newest sessions are kept.
			$facts[self::FACT] = array_slice([...$linked, $tokenId], -self::MAX);
			$explanation['facts'] = $facts;
			$detection->setExplanationData($explanation);
			try {
				$this->detections->update($detection);
			} catch (\Throwable $e) {
				$this->logger->warning('Intrusion detection could not link a detection to its session', ['exception' => $e]);
			}
		}
	}
}
