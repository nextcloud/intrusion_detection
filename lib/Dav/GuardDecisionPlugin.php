<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Dav;

use OCA\IntrusionDetection\Guard\DeferredHits;
use OCA\IntrusionDetection\Guard\RequestContext;
use OCP\IUserSession;
use OCP\L10N\IFactory;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Sabre\DAV\Server;
use Sabre\DAV\ServerPlugin;
use Sabre\HTTP\RequestInterface;
use Sabre\HTTP\ResponseInterface;

/**
 * Refuses a WebDAV request whose guard hit with credentials (an injection
 * probe, a trap URL) blocked its address, after Sabre's authentication:
 * WebDAV runs no controller, so the middleware never sees it. A hit decided
 * at the login is refused here; one of a request logged in by its session
 * is decided here. The answer is the one a request guard gives: 403 with
 * the block's reference and `Retry-After`. On requests without a hit it
 * costs two property and array lookups.
 */
class GuardDecisionPlugin extends ServerPlugin {
	/** After the authentication plugin (priority 10), before the session-state plugin */
	public const PRIORITY = 20;

	private ?Server $server = null;

	public function __construct(
		private readonly RequestContext $context,
		private readonly ContainerInterface $container,
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
		return 'intrusion-detection-guard-decisions';
	}

	/**
	 * @return bool false when the request is refused and answered here, which stops Sabre
	 */
	public function beforeMethod(RequestInterface $request, ResponseInterface $response): bool {
		$decision = $this->context->refusal();
		if ($decision === null && DeferredHits::isPending($this->context)) {
			try {
				$decision = $this->container->get(DeferredHits::class)->resolve($this->container->get(IUserSession::class)->getUser());
			} catch (\Throwable $e) {
				$this->logger->error('Intrusion detection could not record a request guard hit', ['exception' => $e]);
				return true;
			}
		}
		if ($decision === null) {
			return true;
		}
		// Answered here rather than thrown: the DAV app logs unknown exceptions as critical.
		$response->setStatus(403);
		$response->setHeader('Retry-After', (string)$decision->getRetryAfter());
		$response->setHeader('Content-Type', 'text/plain; charset=utf-8');
		// The same text core shows when a request guard refuses a request.
		$response->setBody($this->container->get(IFactory::class)->get('lib')->t(
			'Access from your network is temporarily blocked. If you think this is a mistake, contact your administrator and give them this reference: %s',
			[$decision->getReference()]
		));
		// Sabre sends no response for a method a listener stopped.
		$this->server?->sapi->sendResponse($response);
		return false;
	}
}
