<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Db;

use OCP\AppFramework\Db\Entity;
use OCP\DB\Types;

/**
 * One lockdown, running or past (concept section 11.14).
 *
 * @method int getStartedAt()
 * @method void setStartedAt(int $startedAt)
 * @method int getPlannedEnd()
 * @method void setPlannedEnd(int $plannedEnd)
 * @method ?int getEndedAt()
 * @method void setEndedAt(?int $endedAt)
 * @method string getStartedBy()
 * @method void setStartedBy(string $startedBy)
 * @method ?string getEndedBy()
 * @method void setEndedBy(?string $endedBy)
 * @method ?string getReason()
 * @method void setReason(?string $reason)
 * @method ?string getEffects()
 * @method void setEffects(?string $effects)
 * @method ?int getDetectionId()
 * @method void setDetectionId(?int $detectionId)
 */
class Lockdown extends Entity {
	/** Who started or ended a lockdown that nobody started or ended by hand */
	public const ACTOR_AUTOMATIC = 'automatic';
	public const ACTOR_OCC = 'occ';

	protected ?int $startedAt = null;
	protected ?int $plannedEnd = null;
	protected ?int $endedAt = null;
	protected ?string $startedBy = null;
	protected ?string $endedBy = null;
	protected ?string $reason = null;
	protected ?string $effects = null;
	protected ?int $detectionId = null;

	public function __construct() {
		$this->addType('startedAt', Types::BIGINT);
		$this->addType('plannedEnd', Types::BIGINT);
		$this->addType('endedAt', Types::BIGINT);
		$this->addType('startedBy', Types::STRING);
		$this->addType('endedBy', Types::STRING);
		$this->addType('reason', Types::STRING);
		$this->addType('effects', Types::STRING);
		$this->addType('detectionId', Types::BIGINT);
	}

	/**
	 * @return list<string>
	 */
	public function getEffectList(): array {
		$effects = (string)$this->effects;
		return $effects === '' ? [] : explode(',', $effects);
	}

	/**
	 * When it ended or will end: early when someone ended it, else as planned.
	 */
	public function endsAt(): int {
		return $this->endedAt ?? (int)$this->plannedEnd;
	}
}
