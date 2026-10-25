<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Detection\CommonFacts;
use OCA\IntrusionDetection\Login\SessionMarkers;
use OCA\IntrusionDetection\Login\SessionTokenLinker;
use OCP\AppFramework\Db\DoesNotExistException;
use Psr\Log\LoggerInterface;

/**
 * Links detections recorded during a login to the session the login
 * created. Core creates the session token only after the login event, so
 * the detection ids wait in the session ({@see SessionMarkers::LOGIN_DETECTIONS})
 * until its first request, when the token exists ({@see SessionTokenLinker}). A linked detection knows
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
		private readonly SessionTokenLinker $linker,
		private readonly LoggerInterface $logger,
	) {
	}

	/**
	 * @param list<string> $ids
	 */
	public function await(string $uid, array $ids): void {
		if ($ids === []) {
			return;
		}
		$this->state->set(SessionMarkers::LOGIN_DETECTIONS, [
			'uid' => $uid,
			'ids' => array_slice(array_values(array_unique([...$this->waiting($uid), ...$ids])), 0, self::MAX),
		]);
	}

	/**
	 * The detections the account's login in this session recorded that
	 * still wait for its session token.
	 *
	 * @return list<string>
	 */
	public function waiting(string $uid): array {
		$waiting = $this->state->get(SessionMarkers::LOGIN_DETECTIONS);
		return is_array($waiting) && ($waiting['uid'] ?? null) === $uid && is_array($waiting['ids'] ?? null) ? array_values(array_filter($waiting['ids'], 'is_string')) : [];
	}

	/**
	 * Link the waiting detections to the current session token, once.
	 */
	public function linkSession(?string $currentUid): void {
		$this->linker->link(SessionMarkers::LOGIN_DETECTIONS, $currentUid, $this->linkToken(...));
	}

	/**
	 * @param array<string, mixed> $waiting
	 */
	private function linkToken(array $waiting, int $tokenId): void {
		$uid = $waiting['uid'];
		if (!is_array($waiting['ids'] ?? null)) {
			return;
		}
		foreach (array_slice($waiting['ids'], 0, self::MAX) as $id) {
			if (!is_string($id)) {
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
