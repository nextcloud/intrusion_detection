<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Detection;

use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Db\AttemptMapper;
use OCA\IntrusionDetection\Net\SourceKey;
use OCP\AppFramework\Utility\ITimeFactory;

/**
 * Records failed attempts in ids_attempts.
 *
 * The login name and the password are fingerprinted with keys derived from
 * the instance secret before anything is stored; the plain values never
 * leave this method.
 */
class AttemptRecorder {
	/** Attempts are kept this long */
	public const RETENTION = 3600;
	/** One in this many recordings also deletes expired attempts */
	public const CLEANUP_ONE_IN = 50;
	/** Above this many rows the table counts as flooded */
	public const FLOOD_ROWS = 100000;
	/** Under a flood, one in this many low-value attempts is kept */
	public const FLOOD_SAMPLE = 10;

	public function __construct(
		private readonly AttemptMapper $mapper,
		private readonly Fingerprinter $fingerprinter,
		private readonly Settings $settings,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	public function record(
		AttemptKind $kind,
		SourceKey $source,
		?string $nameInput = null,
		?string $uid = null,
		?int $shareId = null,
		#[\SensitiveParameter]
		?string $password = null,
	): AttemptRecord {
		$now = $this->timeFactory->getTime();
		$nameHmac = ($nameInput === null || trim($nameInput) === '') ? null : bin2hex($this->fingerprinter->name($nameInput));
		$candidates = [];
		$fingerprint = null;
		if ($password !== null && $password !== '' && $kind === AttemptKind::PasswordLogin) {
			$candidates = array_map('bin2hex', $this->fingerprinter->passwordCandidates($password));
			$fingerprint = $candidates[0];
		}

		$stored = !$this->sampledOut($kind, $now);
		if ($stored) {
			$this->mapper->insert($kind, $source->ipKey, $source->netKey, $nameHmac, $uid, $shareId, $fingerprint, $now);
		}
		if ($this->oneIn(self::CLEANUP_ONE_IN)) {
			$this->mapper->deleteOlderThan($now - self::RETENTION);
		}

		return new AttemptRecord($kind, $source, $nameHmac, $uid, $shareId, $fingerprint, $candidates, $now, $stored);
	}

	/**
	 * Under a flood of more than FLOOD_ROWS attempts, unknown share tokens and
	 * reset requests are sampled. Logins are always kept.
	 */
	private function sampledOut(AttemptKind $kind, int $now): bool {
		if ($kind !== AttemptKind::UnknownShareToken && $kind !== AttemptKind::PasswordReset) {
			return false;
		}
		if ($this->settings->getInt(GlobalSettings::ATTEMPTS_FLOOD_UNTIL) <= $now) {
			return false;
		}
		return !$this->oneIn(self::FLOOD_SAMPLE);
	}

	private function oneIn(int $n): bool {
		return random_int(1, $n) === 1;
	}
}
