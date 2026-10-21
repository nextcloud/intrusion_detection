<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Dav;

use OCA\IntrusionDetection\SessionState\SessionState;
use OCA\IntrusionDetection\SessionState\SessionStateRules;
use OCP\IUserSession;
use Psr\Log\LoggerInterface;
use Sabre\DAV\Exception\Forbidden;
use Sabre\DAV\Server;
use Sabre\DAV\ServerPlugin;
use Sabre\HTTP\RequestInterface;
use Sabre\HTTP\ResponseInterface;

/**
 * Applies the session-state rules to WebDAV requests, after Sabre's
 * authentication. A blocked request gets 403 and a header that says why
 * (e.g. `X-Nextcloud-Password-Change: required`). The 403 is Sabre's own
 * Forbidden, which the DAV app logs at debug level only. A rate limit gets
 * 429 with `Retry-After`.
 * Nothing but one session read happens while no rule applies; a failure
 * lets the request pass.
 */
class SessionStatePlugin extends ServerPlugin {
	/** After the authentication plugin (priority 10) */
	public const PRIORITY = 30;

	public function __construct(
		private readonly SessionStateRules $rules,
		private readonly SessionState $state,
		private readonly IUserSession $userSession,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function initialize(Server $server): void {
		$server->on('beforeMethod:*', $this->beforeMethod(...), self::PRIORITY);
	}

	#[\Override]
	public function getPluginName(): string {
		return 'intrusion-detection-session-state';
	}

	/**
	 * @return bool false when the request is answered here (a rate limit), which stops Sabre
	 * @throws Forbidden
	 */
	public function beforeMethod(RequestInterface $request, ResponseInterface $response): bool {
		try {
			if (!$this->userSession->isLoggedIn()) {
				return true;
			}
			$block = $this->rules->checkDav($this->state, $request->getMethod(), $request->getUrl());
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not check the session state of a WebDAV request', ['exception' => $e]);
			return true;
		}
		if ($block !== null && $block->isRateLimit()) {
			// Answered here rather than thrown: the DAV app logs unknown exceptions as critical.
			$response->setStatus(429);
			$response->setHeader('Retry-After', (string)$block->retryAfter);
			$response->setHeader('Content-Type', 'text/plain; charset=utf-8');
			$response->setBody($block->message);
			return false;
		}
		if ($block !== null) {
			$response->setHeader($block->davHeader, 'required');
			throw new Forbidden($block->message);
		}
		return true;
	}
}
