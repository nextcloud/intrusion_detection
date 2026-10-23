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
 * A change that waits for the approval of a second administrator, or a
 * login that waits for an administrator's approval.
 *
 * @method string getKind()
 * @method void setKind(string $kind)
 * @method string getSubjectUid()
 * @method void setSubjectUid(string $subjectUid)
 * @method string getRequestedBy()
 * @method void setRequestedBy(string $requestedBy)
 * @method ?string getGroupId()
 * @method void setGroupId(?string $groupId)
 * @method ?string getIp()
 * @method void setIp(?string $ip)
 * @method string getStatus()
 * @method void setStatus(string $status)
 * @method ?string getDecidedBy()
 * @method void setDecidedBy(?string $decidedBy)
 * @method int getCreatedAt()
 * @method void setCreatedAt(int $createdAt)
 * @method ?int getDecidedAt()
 * @method void setDecidedAt(?int $decidedAt)
 * @method int getExpiresAt()
 * @method void setExpiresAt(int $expiresAt)
 * @method ?string getPayload()
 * @method void setPayload(?string $payload)
 *
 * @psalm-type HeldChange = array{op: string, values?: array<string, mixed>, check?: string, mode?: ?string, responses?: ?list<mixed>, params?: array<string, mixed>}
 */
class Approval extends Entity implements \JsonSerializable {
	public const KIND_ADMIN_GRANT = 'admin_grant';
	/** A login that nothing else could confirm; requested by the account itself */
	public const KIND_LOGIN = 'login';
	/** A settings change that switches the four-eyes approval off; the change is the payload */
	public const KIND_SETTINGS = 'settings';

	public const STATUS_PENDING = 'pending';
	public const STATUS_APPROVED = 'approved';
	public const STATUS_REJECTED = 'rejected';
	public const STATUS_EXPIRED = 'expired';

	protected ?string $kind = null;
	protected ?string $subjectUid = null;
	protected ?string $requestedBy = null;
	protected ?string $groupId = null;
	protected ?string $ip = null;
	protected ?string $status = null;
	protected ?string $decidedBy = null;
	protected ?int $createdAt = null;
	protected ?int $decidedAt = null;
	protected ?int $expiresAt = null;
	protected ?string $payload = null;

	public function __construct() {
		$this->addType('kind', Types::STRING);
		$this->addType('subjectUid', Types::STRING);
		$this->addType('requestedBy', Types::STRING);
		$this->addType('groupId', Types::STRING);
		$this->addType('ip', Types::STRING);
		$this->addType('status', Types::STRING);
		$this->addType('decidedBy', Types::STRING);
		$this->addType('createdAt', Types::BIGINT);
		$this->addType('decidedAt', Types::BIGINT);
		$this->addType('expiresAt', Types::BIGINT);
		$this->addType('payload', Types::TEXT);
	}

	/**
	 * The settings change a request of the kind `settings` holds, as it was
	 * stored; an empty change for every other kind.
	 *
	 * @return HeldChange
	 */
	public function heldChange(): array {
		$change = json_decode((string)$this->payload, true);
		/** @var HeldChange */
		return is_array($change) && is_string($change['op'] ?? null) ? $change : ['op' => ''];
	}

	public function isPending(): bool {
		return $this->status === self::STATUS_PENDING;
	}

	#[\Override]
	public function jsonSerialize(): array {
		return [
			'id' => $this->getId(),
			'kind' => $this->kind,
			'subject' => $this->subjectUid,
			'requestedBy' => $this->requestedBy,
			'group' => $this->groupId,
			'ip' => $this->ip,
			'status' => $this->status,
			'decidedBy' => $this->decidedBy,
			'createdAt' => $this->createdAt,
			'decidedAt' => $this->decidedAt,
			'expiresAt' => $this->expiresAt,
		];
	}
}
