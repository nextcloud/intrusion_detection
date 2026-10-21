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
 * A decoy credential. Only the keyed fingerprint of its secret is stored;
 * the secret is shown once when the decoy is created.
 *
 * @method ?string getLoginName()
 * @method void setLoginName(?string $loginName)
 * @method string getSecretHmac()
 * @method void setSecretHmac(string $secretHmac)
 * @method string getFormat()
 * @method void setFormat(string $format)
 * @method string getLabel()
 * @method void setLabel(string $label)
 * @method ?string getCreatedBy()
 * @method void setCreatedBy(?string $createdBy)
 * @method int getCreatedAt()
 * @method void setCreatedAt(int $createdAt)
 * @method ?int getLastTriggeredAt()
 * @method void setLastTriggeredAt(?int $lastTriggeredAt)
 * @method int getTriggerCount()
 * @method void setTriggerCount(int $triggerCount)
 */
class Decoy extends Entity implements \JsonSerializable {
	protected ?string $loginName = null;
	protected ?string $secretHmac = null;
	protected ?string $format = null;
	protected ?string $label = null;
	protected ?string $createdBy = null;
	protected ?int $createdAt = null;
	protected ?int $lastTriggeredAt = null;
	protected ?int $triggerCount = null;

	public function __construct() {
		$this->addType('loginName', Types::STRING);
		$this->addType('secretHmac', Types::STRING);
		$this->addType('format', Types::STRING);
		$this->addType('label', Types::STRING);
		$this->addType('createdBy', Types::STRING);
		$this->addType('createdAt', Types::BIGINT);
		$this->addType('lastTriggeredAt', Types::BIGINT);
		$this->addType('triggerCount', Types::INTEGER);
	}

	/**
	 * Everything about the decoy except the fingerprint of its secret.
	 */
	#[\Override]
	public function jsonSerialize(): array {
		return [
			'id' => $this->getId(),
			'label' => $this->label,
			'loginName' => $this->loginName,
			'format' => $this->format,
			'createdBy' => $this->createdBy,
			'createdAt' => $this->createdAt,
			'lastTriggeredAt' => $this->lastTriggeredAt,
			'triggerCount' => $this->triggerCount ?? 0,
		];
	}
}
