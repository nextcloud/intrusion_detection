<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\IntrusionDetection\Check\Checks\ReservedName\ReservedName;
use OCA\IntrusionDetection\Config\Keys;
use OCA\IntrusionDetection\Event\SettingChangedEvent;
use OCA\IntrusionDetection\Traps\TrapNameCollisions;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use Psr\Log\LoggerInterface;

/**
 * Looks the reserved names up again whenever they change, however they were
 * changed (admin page, occ, settings import).
 *
 * @template-implements IEventListener<SettingChangedEvent>
 */
class TrapNamesChangedListener implements IEventListener {
	public function __construct(
		private readonly TrapNameCollisions $collisions,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function handle(Event $event): void {
		if (!$event instanceof SettingChangedEvent || $event->getKey() !== Keys::param(ReservedName::ID, 'names')) {
			return;
		}
		try {
			$this->collisions->refresh();
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not look the reserved names up', ['exception' => $e]);
		}
	}
}
