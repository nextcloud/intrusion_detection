<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Takeover\Signals;

use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Risk\RiskScorer;
use OCA\IntrusionDetection\Takeover\IRiskyLoginSignal;
use OCA\IntrusionDetection\Takeover\RiskyLogin;

/**
 * The session's login was a password login from a browser or app the
 * account had not remembered, and its address has at least an elevated
 * risk score. The score is the address's current one, which the scorer
 * keeps for a minute.
 */
class UnknownDeviceSignal implements IRiskyLoginSignal {
	private const PASSWORD_METHODS = [LoginHistory::METHOD_PASSWORD, LoginHistory::METHOD_CLIENT_PASSWORD];

	public function __construct(
		private readonly LoginHistory $history,
		private readonly RiskScorer $scorer,
	) {
	}

	#[\Override]
	public function riskyLogin(string $uid, ?int $sessionTokenId): ?RiskyLogin {
		if ($sessionTokenId === null || !$this->scorer->isEnabled()) {
			return null;
		}
		$login = $this->history->forSession($uid, $sessionTokenId);
		if ($login === null || $login->knownDevice || !in_array($login->method, self::PASSWORD_METHODS, true)) {
			return null;
		}
		$source = $login->ip === null ? null : SourceKey::tryFromIp($login->ip);
		if ($source === null) {
			return null;
		}
		$risk = $this->scorer->score($source);
		return $risk->score >= $risk->tierElevated ? new RiskyLogin($login->createdAt, RiskyLogin::REASON_UNKNOWN_DEVICE) : null;
	}
}
