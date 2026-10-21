<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\DAV\Events\SabrePluginAddEvent;
use OCA\IntrusionDetection\Dav\GuardDecisionPlugin;
use OCA\IntrusionDetection\Dav\SessionStatePlugin;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * Adds the guard decision and session-state plugins to the WebDAV servers.
 *
 * @template-implements IEventListener<SabrePluginAddEvent>
 */
class SabrePluginAddListener implements IEventListener {
	public function __construct(
		private readonly ContainerInterface $container,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function handle(Event $event): void {
		if (!$event instanceof SabrePluginAddEvent) {
			return;
		}
		try {
			$event->getServer()->addPlugin($this->container->get(GuardDecisionPlugin::class));
			$event->getServer()->addPlugin($this->container->get(SessionStatePlugin::class));
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not add its WebDAV plugin', ['exception' => $e]);
		}
	}
}
