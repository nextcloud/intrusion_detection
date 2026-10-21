<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Admin;

use OCA\IntrusionDetection\Db\Ban;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IL10N;

/**
 * @psalm-import-type IntrusionDetectionBan from ResponseDefinitions
 */
class BanPresenter {
	public function __construct(
		private readonly CheckNames $names,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * @return IntrusionDetectionBan
	 */
	public function present(Ban $ban, IL10N $l): array {
		$checkId = $ban->getCheckId();
		return [
			'id' => (int)$ban->getId(),
			'reference' => $ban->getDisplayReference(),
			'cidr' => $ban->getCidr(),
			'scope' => $ban->getScope(),
			'level' => $ban->getLevel(),
			'checkId' => $checkId,
			'checkName' => $this->names->name($checkId, $l),
			'detectionId' => $ban->getDetectionId(),
			'createdBy' => $ban->getCreatedBy(),
			'note' => $ban->getNote(),
			'createdAt' => $ban->getCreatedAt(),
			'expiresAt' => $ban->getExpiresAt(),
			'liftedAt' => $ban->getLiftedAt(),
			'liftedBy' => $ban->getLiftedBy(),
			'liftNote' => $ban->getLiftNote(),
			'active' => $ban->isActive($this->timeFactory->getTime()),
		];
	}

	/**
	 * @param list<Ban> $bans
	 * @return list<IntrusionDetectionBan>
	 */
	public function presentAll(array $bans, IL10N $l): array {
		return array_map(fn (Ban $ban): array => $this->present($ban, $l), $bans);
	}
}
