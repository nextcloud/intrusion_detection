<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Dav;

use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Share\FederationPartners;
use Psr\Log\LoggerInterface;
use Sabre\DAV\Auth\Plugin as AuthPlugin;
use Sabre\DAV\Server;
use Sabre\DAV\ServerPlugin;
use Sabre\HTTP\RequestInterface;
use Sabre\HTTP\ResponseInterface;

/**
 * Tells {@see FederationPartners} which share token a public WebDAV request
 * was authenticated with, after Sabre's authentication. The principal of a
 * public share ends in its token, however the request sent it (Basic auth,
 * the URL, or an access token of a federated share).
 */
class FederatedShareUsePlugin extends ServerPlugin {
	/** After the authentication plugin (priority 10) */
	public const PRIORITY = 20;

	private ?Server $server = null;

	public function __construct(
		private readonly RemoteAddressResolver $addresses,
		private readonly FederationPartners $partners,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function initialize(Server $server): void {
		$this->server = $server;
		$server->on('beforeMethod:*', $this->beforeMethod(...), self::PRIORITY);
	}

	#[\Override]
	public function getPluginName(): string {
		return 'intrusion-detection-federated-shares';
	}

	public function beforeMethod(RequestInterface $request, ResponseInterface $response): bool {
		try {
			$auth = $this->server?->getPlugin('auth');
			$principal = $auth instanceof AuthPlugin ? $auth->getCurrentPrincipal() : null;
			if (!is_string($principal) || $principal === '') {
				return true;
			}
			$source = $this->addresses->current();
			if ($source !== null) {
				$this->partners->observe($source, basename($principal));
			}
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not look at a federated share access', ['exception' => $e]);
		}
		return true;
	}
}
