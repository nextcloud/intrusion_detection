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
 * An address or network was blocked, or an existing block was raised to a higher level.
 *
 * Webhooks get the payload of {@see EventPayloads::banCreated()}.
 */
class BanCreatedEvent extends Event implements IWebhookCompatibleEvent {
	public function __construct(
		private readonly Ban $ban,
		private readonly bool $raised = false,
		private readonly ?EventPayloads $payloads = null,
	) {
		parent::__construct();
	}

	public function getBan(): Ban {
		return $this->ban;
	}

	/**
	 * Whether an existing block was raised rather than a new one created.
	 */
	public function isRaised(): bool {
		return $this->raised;
	}

	#[\Override]
	public function getWebhookSerializable(): array {
		return ($this->payloads ?? Server::get(EventPayloads::class))->banCreated($this->ban, $this->raised);
	}
}
