<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\IntrusionDetection\Event\BanCreatedEvent;
use OCA\IntrusionDetection\Event\BanLiftedEvent;
use OCA\IntrusionDetection\Export\FirewallExporter;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use Psr\Log\LoggerInterface;

/**
 * Updates the firewall export whenever a block is created, raised or lifted.
 *
 * @template-implements IEventListener<BanCreatedEvent|BanLiftedEvent>
 */
class FirewallExportListener implements IEventListener {
	public function __construct(
		private readonly FirewallExporter $exporter,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function handle(Event $event): void {
		try {
			if ($event instanceof BanCreatedEvent) {
				$this->exporter->banChanged($event->getBan(), false);
			} elseif ($event instanceof BanLiftedEvent) {
				$this->exporter->banChanged($event->getBan(), true);
			}
		} catch (\Throwable $e) {
			// The block itself is in place; only the export is behind.
			$this->logger->error('Intrusion detection could not update the firewall export', ['exception' => $e]);
		}
	}
}
