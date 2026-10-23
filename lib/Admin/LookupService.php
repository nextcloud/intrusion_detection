<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Admin;

use OCA\IntrusionDetection\Address\AddressResolver;
use OCA\IntrusionDetection\Check\Checks\StepUpRefused\StepUpRefused;
use OCA\IntrusionDetection\Confirm\StepUpReference;
use OCA\IntrusionDetection\Db\Ban;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\BanService;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IL10N;
use OCP\IUserManager;

/**
 * "Look up a reference, address or user" on the admin page.
 *
 * A blocked visitor reports the reference shown on the block page
 * (K7Q2-MPXA, in any case, with or without the dash), a refused login the
 * reference of its refusal ({@see StepUpReference}). An address shows the
 * blocks that cover it and its recent detections; an account shows the
 * detections about it.
 *
 * @psalm-import-type IntrusionDetectionLookup from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionDetection from ResponseDefinitions
 */
class LookupService {
	/** Detections shown for an address or an account */
	public const DETECTION_LIMIT = 20;
	/** ... from this many days back */
	public const DETECTION_DAYS = 30;
	public const MAX_QUERY_LENGTH = 255;

	public function __construct(
		private readonly BanMapper $banMapper,
		private readonly DetectionMapper $detectionMapper,
		private readonly AddressResolver $addresses,
		private readonly IUserManager $userManager,
		private readonly BanPresenter $bans,
		private readonly DetectionPresenter $detections,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * Whether the input has the shape of a block reference.
	 */
	public static function isReference(string $input): bool {
		$reference = Ban::normaliseReference($input);
		return strlen($reference) === 8 && strspn($reference, BanService::REFERENCE_CHARS) === 8;
	}

	/**
	 * @return IntrusionDetectionLookup
	 */
	public function lookup(string $query, IL10N $l): array {
		$query = trim($query);
		$result = ['kind' => 'none', 'query' => $query, 'bans' => [], 'detections' => [], 'user' => null];
		if ($query === '' || mb_strlen($query) > self::MAX_QUERY_LENGTH) {
			return $result;
		}

		if (self::isReference($query)) {
			try {
				$ban = $this->banMapper->findByReference($query);
				$result['kind'] = 'reference';
				$result['bans'] = [$this->bans->present($ban, $l)];
				$detectionId = $ban->getDetectionId();
				if ($detectionId !== null) {
					try {
						$result['detections'] = [$this->detections->row($this->detectionMapper->findById($detectionId), $l)];
					} catch (DoesNotExistException) {
						// Detections are deleted earlier than the blocks they caused.
					}
				}
				return $result;
			} catch (DoesNotExistException) {
				// Not a block; it may be an account name.
			}
		}

		$refusal = $this->refusal($query);
		if ($refusal !== null) {
			$result['kind'] = 'reference';
			$result['detections'] = [$this->detections->row($refusal, $l)];
			return $result;
		}

		$source = SourceKey::tryFromIp(explode('/', $query, 2)[0]);
		if ($source !== null) {
			$result['kind'] = 'address';
			$result['query'] = $source->ip;
			$result['bans'] = $this->bans->presentAll($this->addresses->activeBans($source), $l);
			$result['detections'] = $this->recentDetections(ip: $source->ip, l: $l);
			return $result;
		}

		$user = $this->userManager->get($query);
		if ($user !== null) {
			$result['kind'] = 'user';
			$result['user'] = ['uid' => $user->getUID(), 'displayName' => $user->getDisplayName()];
			$result['detections'] = $this->recentDetections(uid: $user->getUID(), l: $l);
		}
		return $result;
	}

	private function refusal(string $reference): ?Detection {
		$id = StepUpReference::detectionId($reference);
		if ($id === null) {
			return null;
		}
		try {
			$detection = $this->detectionMapper->findById($id);
		} catch (DoesNotExistException) {
			return null;
		}
		return $detection->getCheckId() === StepUpRefused::ID ? $detection : null;
	}

	/**
	 * @return list<IntrusionDetectionDetection>
	 */
	private function recentDetections(IL10N $l, ?string $ip = null, ?string $uid = null): array {
		return $this->detections->rows($this->detectionMapper->findList(new DetectionFilter(
			uid: $uid,
			ip: $ip,
			since: $this->timeFactory->getTime() - self::DETECTION_DAYS * 86400,
			limit: self::DETECTION_LIMIT,
		)), $l);
	}
}
