<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Sensitive;

use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Confirm\UnconfirmedSessions;
use OCA\IntrusionDetection\Db\RiskySessionMapper;
use OCA\IntrusionDetection\SessionState\CurrentSession;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IConfig;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * Sessions that a detection made risky from another request: a check that
 * notices something after the fact, or in a background job, marks the
 * session it is about by the database id of the session's token
 * (ids_risky_sessions).
 *
 * Kept in the database rather than the memory cache: the mark must reach
 * every web server, survive a cache restart and work without a distributed
 * cache, and it is read only when a session tries a sensitive action, which
 * is rare. While no mark can exist (`sensitive_marks_until`, read from the
 * loaded app config) nothing is read at all; otherwise one primary-key read.
 * A mark lasts as long as the session could.
 */
class RiskySessions {
	public function __construct(
		private readonly Settings $settings,
		private readonly ITimeFactory $timeFactory,
		private readonly IConfig $config,
		private readonly ContainerInterface $container,
		private readonly LoggerInterface $logger,
	) {
	}

	public function mark(int $tokenId, string $uid, string $checkId, ?int $detectionId): void {
		$now = $this->timeFactory->getTime();
		$expires = $now + max(
			$this->config->getSystemValueInt('remember_login_cookie_lifetime', UnconfirmedSessions::DEFAULT_REMEMBER_LIFETIME),
			$this->config->getSystemValueInt('session_lifetime', UnconfirmedSessions::DEFAULT_SESSION_LIFETIME),
		);
		$this->container->get(RiskySessionMapper::class)->record($tokenId, $uid, $checkId, $detectionId, $now, $expires);
		if ($this->settings->getInt(GlobalSettings::SENSITIVE_MARKS_UNTIL) < $expires) {
			$this->settings->setGlobal(GlobalSettings::SENSITIVE_MARKS_UNTIL, $expires);
		}
	}

	/**
	 * Whether the current request's session is marked.
	 */
	public function isMarked(string $uid): bool {
		$now = $this->timeFactory->getTime();
		if ($this->settings->getInt(GlobalSettings::SENSITIVE_MARKS_UNTIL) <= $now) {
			return false;
		}
		try {
			$tokenId = $this->container->get(CurrentSession::class)->tokenId();
			return $tokenId !== null && $this->container->get(RiskySessionMapper::class)->find($tokenId, $uid, $now) !== null;
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not read whether a session is marked risky', ['exception' => $e]);
			return false;
		}
	}
}
