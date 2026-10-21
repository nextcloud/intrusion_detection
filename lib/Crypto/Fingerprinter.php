<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Crypto;

use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IConfig;

/**
 * Keyed fingerprints of secrets and identifiers.
 *
 * Every key is derived from the instance `secret` in config.php, never from a
 * value stored in the database, so a database dump alone is not enough to test
 * guesses against the stored fingerprints.
 *
 * Nothing this class returns may ever be logged.
 */
class Fingerprinter {
	/** During this many seconds after UTC midnight, yesterday's password key is still tried */
	public const MIDNIGHT_OVERLAP = 3600;

	/** @var array<string, string> derived keys, per request */
	private array $keys = [];

	public function __construct(
		private readonly IConfig $config,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * 16-byte fingerprint of an attempted password under today's key.
	 */
	public function password(string $password): string {
		return $this->passwordForDay($password, $this->today());
	}

	/**
	 * The fingerprints a stored one may have been made with: today's, and in
	 * the first hour after midnight also yesterday's, so that a run of
	 * attempts that crosses midnight is still recognised as one.
	 *
	 * @return list<string>
	 */
	public function passwordCandidates(string $password): array {
		$candidates = [$this->password($password)];
		$now = $this->timeFactory->getTime();
		if ($now % 86400 < self::MIDNIGHT_OVERLAP) {
			$candidates[] = $this->passwordForDay($password, gmdate('Y-m-d', $now - 86400));
		}
		return $candidates;
	}

	/**
	 * The fingerprints under which a flagged password stays recognisable for
	 * the whole flag duration (at most a day): today's and tomorrow's, since
	 * the key changes at UTC midnight.
	 *
	 * @return list<string>
	 */
	public function passwordFlagFingerprints(#[\SensitiveParameter] string $password): array {
		return [
			$this->password($password),
			$this->passwordForDay($password, gmdate('Y-m-d', $this->timeFactory->getTime() + 86400)),
		];
	}

	/**
	 * 16-byte fingerprint of a login name, reset input or share token,
	 * lower-cased and trimmed first.
	 */
	public function name(#[\SensitiveParameter] string $input): string {
		return substr(hash_hmac('sha256', mb_strtolower(trim($input)), $this->key('name'), true), 0, 16);
	}

	/**
	 * 16-byte fingerprint of a share token, trimmed but not lower-cased:
	 * tokens are case-sensitive, so tokens that differ only in case are
	 * different guesses.
	 */
	public function shareToken(#[\SensitiveParameter] string $token): string {
		return substr(hash_hmac('sha256', trim($token), $this->key('share_token'), true), 0, 16);
	}

	/**
	 * 32-byte fingerprint of a decoy secret.
	 */
	public function decoy(string $secret): string {
		return hash_hmac('sha256', $secret, $this->key('decoy'), true);
	}

	/**
	 * Short base64url key for a credential, for memory-cache keys only. It is
	 * never written to the database.
	 */
	public function credential(#[\SensitiveParameter] string $credential): string {
		$raw = substr(hash_hmac('sha256', $credential, $this->key('credential/' . $this->today()), true), 0, 12);
		return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
	}

	/**
	 * 32-byte fingerprint of a known-device id from the device cookie.
	 */
	public function device(#[\SensitiveParameter] string $deviceId): string {
		return hash_hmac('sha256', $deviceId, $this->key('device'), true);
	}

	/**
	 * 64 hex characters: a keyed hash of a watched setting's value, so the
	 * snapshot can tell a change without holding the value, and a stored hash
	 * of a secret cannot be tested against guesses without config.php.
	 */
	public function setting(#[\SensitiveParameter] string $value): string {
		return hash_hmac('sha256', $value, $this->key('setting'));
	}

	/**
	 * 32 hex characters: a keyed fingerprint of a session id, so a session
	 * can be recognised later without storing its id, which is the secret of
	 * its token.
	 */
	public function session(#[\SensitiveParameter] string $sessionId): string {
		return bin2hex(substr(hash_hmac('sha256', $sessionId, $this->key('session'), true), 0, 16));
	}

	/**
	 * 64 hex characters: a keyed fingerprint of a lock link's token, so the
	 * link can be checked without storing the token.
	 */
	public function lockToken(#[\SensitiveParameter] string $token): string {
		return hash_hmac('sha256', $token, $this->key('lock_link'));
	}

	private function passwordForDay(string $password, string $day): string {
		return substr(hash_hmac('sha256', $password, $this->key('password/' . $day), true), 0, 16);
	}

	private function today(): string {
		return gmdate('Y-m-d', $this->timeFactory->getTime());
	}

	private function key(string $purpose): string {
		if (!isset($this->keys[$purpose])) {
			$secret = $this->config->getSystemValueString('secret', '');
			if ($secret === '') {
				// Every installed server has a secret; without one the fingerprints
				// would be unkeyed and testable against a database dump.
				throw new \RuntimeException('The instance secret is missing from config.php');
			}
			$this->keys[$purpose] = hash_hmac('sha256', 'intrusion_detection/' . $purpose, $secret, true);
		}
		return $this->keys[$purpose];
	}
}
