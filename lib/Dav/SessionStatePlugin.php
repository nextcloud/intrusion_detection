<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Dav;

use OCA\IntrusionDetection\SessionState\RequestTarget;
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
 * Forbidden, which the DAV app logs at debug level only.
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
	 * @throws Forbidden
	 */
	public function beforeMethod(RequestInterface $request, ResponseInterface $response): void {
		try {
			if (!$this->userSession->isLoggedIn()) {
				return;
			}
			$block = $this->rules->check($this->state, RequestTarget::dav($request->getMethod(), $request->getUrl()));
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not check the session state of a WebDAV request', ['exception' => $e]);
			return;
		}
		if ($block !== null) {
			$response->setHeader($block->davHeader, 'required');
			throw new Forbidden($block->message);
		}
	}
}
