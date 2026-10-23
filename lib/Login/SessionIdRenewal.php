<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Login;

use OCP\Session\ISessionIdRenewer;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * Gives the current session a new id through core's ISessionIdRenewer.
 * The session keeps its session token, and with it the token id that the
 * login history, detections and app password origins refer to. Servers
 * without that API keep the session id.
 */
class SessionIdRenewal {
	public function __construct(
		private readonly ContainerInterface $container,
		private readonly LoggerInterface $logger,
	) {
	}

	/**
	 * @return bool whether the session has a new id
	 */
	public function renew(): bool {
		if (!$this->available()) {
			return false;
		}
		try {
			$this->container->get(ISessionIdRenewer::class)->renewSessionId();
			return true;
		} catch (\Throwable $e) {
			$this->logger->warning('Intrusion detection could not give the session a new id', ['exception' => $e]);
			return false;
		}
	}

	protected function available(): bool {
		return interface_exists(ISessionIdRenewer::class);
	}
}
