<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Event;

use OCA\IntrusionDetection\Db\Detection;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IWebhookCompatibleEvent;
use OCP\Server;

/**
 * A check found something, and the responses have run (or were recorded as
 * "would have" in Observe mode).
 *
 * Webhooks get the payload of {@see EventPayloads::detection()}.
 */
class DetectionCreatedEvent extends Event implements IWebhookCompatibleEvent {
	public function __construct(
		private readonly Detection $detection,
		private readonly ?EventPayloads $payloads = null,
	) {
		parent::__construct();
	}

	public function getDetection(): Detection {
		return $this->detection;
	}

	#[\Override]
	public function getWebhookSerializable(): array {
		return ($this->payloads ?? Server::get(EventPayloads::class))->detection($this->detection);
	}
}
