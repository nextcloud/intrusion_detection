<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Response;

use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\FlagMapper;
use OCA\IntrusionDetection\Net\SourceKey;
use OCP\AppFramework\Utility\ITimeFactory;

/**
 * Flagged addresses, networks and passwords. A flag means: a successful
 * login from there (or with that password) needs extra confirmation.
 * Only the step-up logic reads flags.
 */
class FlaggedSources {
	public const REASON_ATTACK = 'attack';
	public const REASON_BAN_EXPIRED = 'ban_expired';
	public const REASON_DISTRIBUTED = 'distributed';
	public const REASON_USER_DENIED = 'user_denied';
	public const REASON_SPRAYED = 'sprayed';

	public function __construct(
		private readonly FlagMapper $mapper,
		private readonly Settings $settings,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * @return int when the flag expires
	 */
	public function flagSource(SourceKey $source, string $reason, ?int $detectionId = null, ?int $duration = null): int {
		$expires = $this->timeFactory->getTime() + ($duration ?? $this->settings->getInt(GlobalSettings::FLAG_DURATION));
		$this->mapper->flag(self::sourceKey($source), $reason, $expires, $detectionId);
		return $expires;
	}

	/**
	 * @param string $fingerprint hex password fingerprint
	 */
	public function flagPassword(string $fingerprint, ?int $detectionId = null, ?int $duration = null): void {
		$expires = $this->timeFactory->getTime() + ($duration ?? $this->settings->getInt(GlobalSettings::FLAG_DURATION));
		$this->mapper->flag(self::passwordKey($fingerprint), self::REASON_SPRAYED, $expires, $detectionId);
	}

	/**
	 * The flag on the address or its network, if any.
	 */
	public function sourceFlag(SourceKey $source): ?string {
		$keys = array_values(array_unique([self::sourceKey($source), 'net:' . $source->netKey]));
		$flags = $this->mapper->active($keys, $this->timeFactory->getTime());
		return $flags === [] ? null : (string)reset($flags);
	}

	/**
	 * Whether any of the password fingerprints is flagged.
	 *
	 * @param list<string> $fingerprints hex
	 */
	public function isPasswordFlagged(array $fingerprints): bool {
		if ($fingerprints === []) {
			return false;
		}
		$keys = array_map(static fn (string $f): string => self::passwordKey($f), $fingerprints);
		return $this->mapper->active($keys, $this->timeFactory->getTime()) !== [];
	}

	public function flagNetwork(SourceKey $source, string $reason, ?int $detectionId = null): void {
		$expires = $this->timeFactory->getTime() + $this->settings->getInt(GlobalSettings::FLAG_DURATION);
		$this->mapper->flag('net:' . $source->netKey, $reason, $expires, $detectionId);
	}

	public function unflagSource(SourceKey $source): void {
		$this->mapper->unflag(self::sourceKey($source));
		$this->mapper->unflag('net:' . $source->netKey);
	}

	private static function sourceKey(SourceKey $source): string {
		return 'ip:' . $source->ipKey;
	}

	private static function passwordKey(string $fingerprint): string {
		return 'fp:' . $fingerprint;
	}
}
