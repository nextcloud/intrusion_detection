<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SessionState;

use OCP\ISession;
use Psr\Log\LoggerInterface;

/**
 * What intrusion detection keeps in the PHP session: named markers such as
 * "this session must change its password first", all under one session key.
 *
 * Reading is one session lookup, which is what keeps the session-state
 * checks on normal requests cheap. Writes need an open session; where core
 * has closed it already, they fail and are logged, never thrown.
 */
class SessionState {
	public const SESSION_KEY = 'intrusion_detection.state';

	/** A new password must be chosen before anything else (concept section 11.7) */
	public const PASSWORD_CHANGE = 'password_change';
	/** The login waits for its extra confirmation, or was refused (concept section 11.5) */
	public const STEP_UP = 'step_up';
	/** How the login of this session was confirmed, when it needed confirmation */
	public const CONFIRMATION = 'confirmation';
	/** Detections recorded at login, to be linked to the session token once it exists */
	public const LOGIN_DETECTIONS = 'login_detections';

	public function __construct(
		private readonly ISession $session,
		private readonly LoggerInterface $logger,
	) {
	}

	/**
	 * @return array<string, array<string, mixed>>
	 */
	public function all(): array {
		$state = $this->session->get(self::SESSION_KEY);
		return is_array($state) ? $state : [];
	}

	public function isEmpty(): bool {
		return $this->all() === [];
	}

	/**
	 * @return ?array<string, mixed>
	 */
	public function get(string $name): ?array {
		$marker = $this->all()[$name] ?? null;
		return is_array($marker) ? $marker : null;
	}

	/**
	 * @param array<string, mixed> $data
	 * @return bool whether it was stored
	 */
	public function set(string $name, array $data): bool {
		$state = $this->all();
		$state[$name] = $data;
		return $this->write($state);
	}

	/**
	 * @return bool whether the marker is gone now
	 */
	public function remove(string $name): bool {
		$state = $this->all();
		if (!isset($state[$name])) {
			return true;
		}
		unset($state[$name]);
		return $this->write($state);
	}

	/**
	 * @param array<string, array<string, mixed>> $state
	 */
	private function write(array $state): bool {
		try {
			if ($state === []) {
				$this->session->remove(self::SESSION_KEY);
			} else {
				$this->session->set(self::SESSION_KEY, $state);
			}
			return true;
		} catch (\Throwable $e) {
			$this->logger->warning('Intrusion detection could not update the session state', ['exception' => $e]);
			return false;
		}
	}
}
