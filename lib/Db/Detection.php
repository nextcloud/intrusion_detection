<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Db;

use OCA\IntrusionDetection\Definition\Severity;
use OCP\AppFramework\Db\SnowflakeAwareEntity;
use OCP\DB\Types;

/**
 * One detection: what a check found, the facts that explain it, and what was done.
 *
 * Never holds a password, a password fingerprint, a decoy secret, a share
 * token or a credential.
 *
 * @method string getCheckId()
 * @method void setCheckId(string $checkId)
 * @method value-of<Severity> getSeverity()
 * @method void setSeverity(string $severity)
 * @method ?bool getEnforced()
 * @method void setEnforced(?bool $enforced)
 * @method ?string getIp()
 * @method void setIp(?string $ip)
 * @method ?string getNetKey()
 * @method void setNetKey(?string $netKey)
 * @method ?string getUid()
 * @method void setUid(?string $uid)
 * @method ?int getShareId()
 * @method void setShareId(?int $shareId)
 * @method ?string getMergeKey()
 * @method void setMergeKey(?string $mergeKey)
 * @method ?string getExplanation()
 * @method void setExplanation(?string $explanation)
 * @method ?string getActions()
 * @method void setActions(?string $actions)
 * @method ?string getUserVerdict()
 * @method void setUserVerdict(?string $userVerdict)
 * @method ?int getVerdictAt()
 * @method void setVerdictAt(?int $verdictAt)
 * @method int getCreatedTime() when it was created, as a Unix time
 * @method void setCreatedTime(int $createdTime)
 * @method int getLastSeenAt()
 * @method void setLastSeenAt(int $lastSeenAt)
 * @method int getHits()
 * @method void setHits(int $hits)
 */
class Detection extends SnowflakeAwareEntity implements \JsonSerializable {
	use CreatedTimeColumn;

	public const VERDICT_CONFIRMED = 'confirmed';
	public const VERDICT_DENIED = 'denied';

	protected ?string $checkId = null;
	protected ?string $severity = null;
	protected ?bool $enforced = null;
	protected ?string $ip = null;
	protected ?string $netKey = null;
	protected ?string $uid = null;
	protected ?int $shareId = null;
	protected ?string $mergeKey = null;
	protected ?string $explanation = null;
	protected ?string $actions = null;
	protected ?string $userVerdict = null;
	protected ?int $verdictAt = null;
	protected ?int $createdTime = null;
	protected ?int $lastSeenAt = null;
	protected ?int $hits = null;

	public function __construct() {
		$this->addType('checkId', Types::STRING);
		$this->addType('severity', Types::STRING);
		$this->addType('enforced', Types::BOOLEAN);
		$this->addType('ip', Types::STRING);
		$this->addType('netKey', Types::STRING);
		$this->addType('uid', Types::STRING);
		$this->addType('shareId', Types::BIGINT);
		$this->addType('mergeKey', Types::STRING);
		$this->addType('explanation', Types::TEXT);
		$this->addType('actions', Types::TEXT);
		$this->addType('userVerdict', Types::STRING);
		$this->addType('verdictAt', Types::BIGINT);
		$this->addType('createdTime', Types::BIGINT);
		$this->addType('lastSeenAt', Types::BIGINT);
		$this->addType('hits', Types::INTEGER);
	}

	/**
	 * @return array<string, mixed>
	 */
	public function getExplanationData(): array {
		return self::decode($this->explanation);
	}

	/**
	 * @param array<string, mixed> $data
	 */
	public function setExplanationData(array $data): void {
		$this->setExplanation(json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
	}

	/**
	 * @return list<array{type: string, enforced: bool, ref?: mixed, note?: string}>
	 */
	public function getActionList(): array {
		/** @var list<array{type: string, enforced: bool, ref?: mixed, note?: string}> */
		return self::decode($this->actions);
	}

	/**
	 * @param list<array{type: string, enforced: bool, ref?: mixed, note?: string}> $actions
	 */
	public function setActionList(array $actions): void {
		$this->setActions(json_encode($actions, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
	}

	public function isEnforced(): bool {
		return $this->enforced === true;
	}

	#[\Override]
	public function jsonSerialize(): array {
		return [
			'id' => (string)$this->getId(),
			'checkId' => $this->checkId,
			'severity' => $this->severity,
			'enforced' => $this->isEnforced(),
			'ip' => $this->ip,
			'netKey' => $this->netKey,
			'uid' => $this->uid,
			'shareId' => $this->shareId,
			'explanation' => $this->getExplanationData(),
			'actions' => $this->getActionList(),
			'userVerdict' => $this->userVerdict,
			'verdictAt' => $this->verdictAt,
			'createdAt' => $this->createdTime,
			'lastSeenAt' => $this->lastSeenAt,
			'hits' => $this->hits,
		];
	}

	/**
	 * @return array<array-key, mixed>
	 */
	private static function decode(?string $json): array {
		if ($json === null || $json === '') {
			return [];
		}
		try {
			$data = json_decode($json, true, 32, JSON_THROW_ON_ERROR);
		} catch (\JsonException) {
			return [];
		}
		return is_array($data) ? $data : [];
	}
}
