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
 * leave this method. Expired attempts are deleted by the cleanup job, never
 * on the path of a failed login.
 */
class AttemptRecorder {
	/** Attempts are kept this long */
	public const RETENTION = 3600;
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
		#[\SensitiveParameter]
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

		return $this->store($kind, $source, $nameHmac, $uid, $shareId, $fingerprint, $candidates, $now);
	}

	/**
	 * Record an access to a share link with a token that does not exist.
	 * Only the token's fingerprint is stored.
	 *
	 * @param bool $lure the request was a possible lure ({@see \OCA\IntrusionDetection\Net\FetchMetadata}): it never makes its address a target of a block
	 * @param ?string $uid the logged-in user who opened the link, if any
	 */
	public function recordUnknownShareToken(SourceKey $source, #[\SensitiveParameter] string $token, bool $lure = false, ?string $uid = null): AttemptRecord {
		$nameHmac = trim($token) === '' ? null : bin2hex($this->fingerprinter->shareToken($token));
		return $this->store(AttemptKind::UnknownShareToken, $source, $nameHmac, $uid, null, null, [], $this->timeFactory->getTime(), $lure);
	}

	/**
	 * How many attempts one stored row of a kind stands for right now. Under
	 * a flood of more than FLOOD_ROWS attempts, unknown share tokens and reset
	 * requests are sampled: one in FLOOD_SAMPLE is kept, and this is
	 * FLOOD_SAMPLE. Logins are always kept, with 1. It is stored with
	 * the row as its weight, which the counts of {@see AttemptMapper} use.
	 */
	public function sampleFactor(AttemptKind $kind, int $now): int {
		return self::isSampledKind($kind) && $this->settings->getInt(GlobalSettings::ATTEMPTS_FLOOD_UNTIL) > $now ? self::FLOOD_SAMPLE : 1;
	}

	/**
	 * @param list<string> $candidates
	 */
	private function store(AttemptKind $kind, SourceKey $source, ?string $nameHmac, ?string $uid, ?int $shareId, ?string $fingerprint, array $candidates, int $now, bool $lure = false): AttemptRecord {
		$weight = $this->sampleFactor($kind, $now);
		$stored = $weight === 1 || $this->oneIn(self::FLOOD_SAMPLE);
		if ($stored) {
			$this->mapper->insert($kind, $source->ipKey, $source->netKey, $nameHmac, $uid, $shareId, $fingerprint, $now, $weight, $lure);
		}
		return new AttemptRecord($kind, $source, $nameHmac, $uid, $shareId, $fingerprint, $candidates, $now, $stored, $lure);
	}

	private static function isSampledKind(AttemptKind $kind): bool {
		return $kind === AttemptKind::UnknownShareToken || $kind === AttemptKind::PasswordReset;
	}

	protected function oneIn(int $n): bool {
		return random_int(1, $n) === 1;
	}
}
