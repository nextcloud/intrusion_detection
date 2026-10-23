<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Db;

use OCP\AppFramework\Db\SnowflakeAwareEntity;
use OCP\DB\Types;

/**
 * @method string getReference()
 * @method void setReference(string $reference)
 * @method string getCidr()
 * @method void setCidr(string $cidr)
 * @method string getScope()
 * @method void setScope(string $scope)
 * @method string getBanKey()
 * @method void setBanKey(string $banKey)
 * @method int getLevel()
 * @method void setLevel(int $level)
 * @method string getCheckId()
 * @method void setCheckId(string $checkId)
 * @method ?string getDetectionId()
 * @method void setDetectionId(?string $detectionId)
 * @method ?string getCreatedBy()
 * @method void setCreatedBy(?string $createdBy)
 * @method ?string getNote()
 * @method void setNote(?string $note)
 * @method int getCreatedTime() when it was created, as a Unix time
 * @method void setCreatedTime(int $createdTime)
 * @method int getExpiresAt()
 * @method void setExpiresAt(int $expiresAt)
 * @method ?int getLiftedAt()
 * @method void setLiftedAt(?int $liftedAt)
 * @method ?string getLiftedBy()
 * @method void setLiftedBy(?string $liftedBy)
 * @method ?string getLiftNote()
 * @method void setLiftNote(?string $liftNote)
 */
class Ban extends SnowflakeAwareEntity implements \JsonSerializable {
	use CreatedTimeColumn;

	public const SCOPE_IP = 'ip';
	public const SCOPE_NET = 'net';

	protected ?string $reference = null;
	protected ?string $cidr = null;
	protected ?string $scope = null;
	protected ?string $banKey = null;
	protected ?int $level = null;
	protected ?string $checkId = null;
	protected ?string $detectionId = null;
	protected ?string $createdBy = null;
	protected ?string $note = null;
	protected ?int $createdTime = null;
	protected ?int $expiresAt = null;
	protected ?int $liftedAt = null;
	protected ?string $liftedBy = null;
	protected ?string $liftNote = null;

	public function __construct() {
		$this->addType('reference', Types::STRING);
		$this->addType('cidr', Types::STRING);
		$this->addType('scope', Types::STRING);
		$this->addType('banKey', Types::STRING);
		$this->addType('level', Types::SMALLINT);
		$this->addType('checkId', Types::STRING);
		$this->addType('detectionId', Types::STRING);
		$this->addType('createdBy', Types::STRING);
		$this->addType('note', Types::STRING);
		$this->addType('createdTime', Types::BIGINT);
		$this->addType('expiresAt', Types::BIGINT);
		$this->addType('liftedAt', Types::BIGINT);
		$this->addType('liftedBy', Types::STRING);
		$this->addType('liftNote', Types::STRING);
	}

	public function isActive(int $now): bool {
		return $this->liftedAt === null && $this->expiresAt > $now;
	}

	/**
	 * The reference as shown to people: two groups of four, e.g. K7Q2-MPXA.
	 */
	public function getDisplayReference(): string {
		return self::formatReference((string)$this->reference);
	}

	public static function formatReference(string $reference): string {
		return strlen($reference) === 8 ? substr($reference, 0, 4) . '-' . substr($reference, 4) : $reference;
	}

	/**
	 * Accept a reference as typed by a person: any case, with or without the dash.
	 */
	public static function normaliseReference(string $input): string {
		return strtoupper(str_replace(['-', ' '], '', trim($input)));
	}

	#[\Override]
	public function jsonSerialize(): array {
		return [
			'id' => (string)$this->getId(),
			'reference' => $this->getDisplayReference(),
			'cidr' => $this->cidr,
			'scope' => $this->scope,
			'level' => $this->level,
			'checkId' => $this->checkId,
			'detectionId' => $this->detectionId,
			'createdBy' => $this->createdBy,
			'note' => $this->note,
			'createdAt' => $this->createdTime,
			'expiresAt' => $this->expiresAt,
			'liftedAt' => $this->liftedAt,
			'liftedBy' => $this->liftedBy,
			'liftNote' => $this->liftNote,
		];
	}
}
