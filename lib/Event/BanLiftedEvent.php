<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Event;

use OCA\IntrusionDetection\Db\Ban;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IWebhookCompatibleEvent;
use OCP\Server;

/**
 * A block was lifted by an administrator before it expired.
 *
 * Webhooks get the payload of {@see EventPayloads::banLifted()}.
 */
class BanLiftedEvent extends Event implements IWebhookCompatibleEvent {
	public function __construct(
		private readonly Ban $ban,
		private readonly ?EventPayloads $payloads = null,
	) {
		parent::__construct();
	}

	public function getBan(): Ban {
		return $this->ban;
	}

	#[\Override]
	public function getWebhookSerializable(): array {
		return ($this->payloads ?? Server::get(EventPayloads::class))->banLifted($this->ban);
	}
}
