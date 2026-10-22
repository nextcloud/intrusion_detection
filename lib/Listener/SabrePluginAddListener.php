<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\DAV\Events\SabrePluginAddEvent;
use OCA\IntrusionDetection\Check\Checks\ShareBruteforce;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Dav\FederatedShareUsePlugin;
use OCA\IntrusionDetection\Dav\GuardDecisionPlugin;
use OCA\IntrusionDetection\Dav\SessionStatePlugin;
use OCP\BeforeSabrePubliclyLoadedEvent;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * Adds the guard decision and session-state plugins to the WebDAV servers,
 * and, while the share link check runs, the federated share plugin to the
 * public WebDAV servers.
 *
 * @template-implements IEventListener<SabrePluginAddEvent|BeforeSabrePubliclyLoadedEvent>
 */
class SabrePluginAddListener implements IEventListener {
	public function __construct(
		private readonly ContainerInterface $container,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function handle(Event $event): void {
		if ($event instanceof BeforeSabrePubliclyLoadedEvent) {
			$this->addPublicPlugins($event);
			return;
		}
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

	private function addPublicPlugins(BeforeSabrePubliclyLoadedEvent $event): void {
		try {
			$server = $event->getServer();
			if ($server instanceof \Sabre\DAV\Server && $this->container->get(CheckSettings::class)->modeState(ShareBruteforce::ID)->runs()) {
				$server->addPlugin($this->container->get(FederatedShareUsePlugin::class));
			}
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not add its public WebDAV plugin', ['exception' => $e]);
		}
	}
}
