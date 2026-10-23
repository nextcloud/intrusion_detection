<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Response;

use OCA\IntrusionDetection\Db\Ban;
use OCA\IntrusionDetection\Db\IPurges;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\Db\FlagMapper;
use OCP\AppFramework\Utility\ITimeFactory;

/**
 * Flagged addresses, networks and passwords. A flag means: a successful
 * login from there (or with that password) needs extra confirmation.
 * The step-up logic and the address risk score read flags.
 *
 * An address that failed a password login with an attack tool's user agent
 * gets a flag of its own (`tool:`), which only the risk score reads.
 *
 * A block that ends by itself flags its address or /24 (the cleanup job);
 * lifting a block removes the flag. An address or network that the safety
 * valve or a suspected reverse proxy keeps from being blocked is not flagged
 * either ({@see BanExemptions::forFlag()}).
 */
class FlaggedSources implements IPurges {
	public const REASON_ATTACK = 'attack';
	public const REASON_BAN_EXPIRED = 'ban_expired';
	public const REASON_DISTRIBUTED = 'distributed';
	public const REASON_USER_DENIED = 'user_denied';
	public const REASON_SPRAYED = 'sprayed';
	/** How long a flag lasts */
	public const DURATION = 86400;
	/** How long an attack tool is remembered for an address */
	public const ATTACK_TOOL_DURATION = 86400;
	/**
	 * Password flags last at most this long: the password fingerprint key
	 * changes daily, and a flag is stored under today's and tomorrow's key
	 * only ({@see \OCA\IntrusionDetection\Crypto\Fingerprinter::passwordFlagFingerprints()}).
	 */
	public const PASSWORD_FLAG_MAX_DURATION = 86400;

	/** @var array<string, ?string> the flag of an address or its network as {@see self::loginFlags()} read it in this request, by address key */
	private array $sourceFlags = [];
	/** @var array<string, ?string> the attack tool flag of an address as {@see self::loginFlags()} read it in this request, by address key */
	private array $toolFlags = [];

	public function __construct(
		private readonly FlagMapper $mapper,
		private readonly BanExemptions $exemptions,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * Delete the flags that ended.
	 */
	#[\Override]
	public function purge(int $now): int {
		return $this->mapper->deleteExpired($now);
	}

	/**
	 * @return ?int when the flag expires; null when the address is not flagged ({@see BanExemptions::forFlag()})
	 */
	public function flagSource(SourceKey $source, string $reason, ?int $detectionId = null, ?int $duration = null): ?int {
		$now = $this->timeFactory->getTime();
		if ($this->exemptions->forFlag($source, false, $now) !== null) {
			return null;
		}
		$this->sourceFlags = [];
		$expires = $now + ($duration ?? self::DURATION);
		$this->mapper->flag(self::sourceKey($source), $reason, $expires, $detectionId, $now);
		return $expires;
	}

	/**
	 * @param string $fingerprint hex password fingerprint
	 * @param ?int $duration seconds, at most PASSWORD_FLAG_MAX_DURATION; DURATION by default
	 * @return int when the flag expires
	 */
	public function flagPassword(string $fingerprint, ?int $detectionId = null, ?int $duration = null): int {
		$now = $this->timeFactory->getTime();
		$expires = $now + min($duration ?? self::DURATION, self::PASSWORD_FLAG_MAX_DURATION);
		$this->mapper->flag(self::passwordKey($fingerprint), self::REASON_SPRAYED, $expires, $detectionId, $now);
		return $expires;
	}

	/**
	 * The flag on the address or its network, if any.
	 */
	public function sourceFlag(SourceKey $source): ?string {
		if (array_key_exists($source->ipKey, $this->sourceFlags)) {
			return $this->sourceFlags[$source->ipKey];
		}
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

	/**
	 * What a password login needs, in one query: whether one of the
	 * password fingerprints is flagged (the result), and the flags of the
	 * address, which {@see self::sourceFlag()} and {@see self::riskFlags()}
	 * then answer for the rest of the request.
	 *
	 * @param list<string> $fingerprints hex
	 */
	public function loginFlags(?SourceKey $source, array $fingerprints): bool {
		$passwordKeys = array_map(static fn (string $f): string => self::passwordKey($f), $fingerprints);
		$sourceKeys = $source === null ? [] : array_values(array_unique([self::sourceKey($source), 'net:' . $source->netKey]));
		if ($passwordKeys === [] && $sourceKeys === []) {
			return false;
		}
		$toolKeys = $source === null ? [] : [self::toolKey($source)];
		$flags = $this->mapper->active([...$passwordKeys, ...$sourceKeys, ...$toolKeys], $this->timeFactory->getTime());
		if ($source !== null) {
			$found = array_intersect_key($flags, array_flip($sourceKeys));
			$this->sourceFlags[$source->ipKey] = $found === [] ? null : (string)reset($found);
			$this->toolFlags[$source->ipKey] = $flags[self::toolKey($source)] ?? null;
		}
		return array_intersect_key($flags, array_flip($passwordKeys)) !== [];
	}

	/**
	 * Flag the network of the address (its /24, or its /64).
	 *
	 * @return bool whether it was flagged ({@see BanExemptions::forFlag()})
	 */
	public function flagNetwork(SourceKey $source, string $reason, ?int $detectionId = null): bool {
		$now = $this->timeFactory->getTime();
		if ($this->exemptions->forFlag($source, true, $now) !== null) {
			return false;
		}
		$this->sourceFlags = [];
		$this->mapper->flag('net:' . $source->netKey, $reason, $now + self::DURATION, $detectionId, $now);
		return true;
	}

	public function unflagSource(SourceKey $source): void {
		$this->sourceFlags = [];
		$this->mapper->unflag(self::sourceKey($source));
		$this->mapper->unflag('net:' . $source->netKey);
	}

	/**
	 * Flag the address or /24 of a block that ended by itself, for
	 * DURATION after its end: a login from there needs confirmation
	 * for a while. IPv6 networks wider than a /64 are not flagged.
	 */
	public function flagEndedBan(Ban $ban): void {
		$key = self::banFlagKey($ban);
		if ($key !== null) {
			$this->mapper->flag($key, self::REASON_BAN_EXPIRED, $ban->getExpiresAt() + self::DURATION, $ban->getDetectionId());
		}
	}

	/**
	 * Remove the flag of a lifted block's address or /24, whatever set it:
	 * whoever lifted the block decided the address is fine.
	 */
	public function unflagBan(Ban $ban): void {
		$key = self::banFlagKey($ban);
		if ($key !== null) {
			$this->mapper->unflag($key);
		}
	}

	/**
	 * Remember for a day that the address used an attack tool.
	 *
	 * @return bool whether the flag was written, false while it lasts long enough
	 */
	public function flagAttackTool(SourceKey $source, string $tool): bool {
		unset($this->toolFlags[$source->ipKey]);
		$now = $this->timeFactory->getTime();
		return $this->mapper->flag(self::toolKey($source), $tool, $now + self::ATTACK_TOOL_DURATION, null, $now);
	}

	/**
	 * The flags the risk score reads, in one query: the attack tool the
	 * address used, and the flag on the address or its network.
	 *
	 * @return array{tool: ?string, source: ?string}
	 */
	public function riskFlags(SourceKey $source): array {
		if (array_key_exists($source->ipKey, $this->toolFlags) && array_key_exists($source->ipKey, $this->sourceFlags)) {
			return ['tool' => $this->toolFlags[$source->ipKey], 'source' => $this->sourceFlags[$source->ipKey]];
		}
		$toolKey = self::toolKey($source);
		$flags = $this->mapper->active(array_values(array_unique([$toolKey, self::sourceKey($source), 'net:' . $source->netKey])), $this->timeFactory->getTime());
		$tool = $flags[$toolKey] ?? null;
		unset($flags[$toolKey]);
		return ['tool' => $tool, 'source' => $flags === [] ? null : (string)reset($flags)];
	}

	/**
	 * The flag key a block's address or network is read under, if any.
	 */
	private static function banFlagKey(Ban $ban): ?string {
		$source = SourceKey::tryFromIpKey($ban->getBanKey());
		if ($source !== null) {
			return self::sourceKey($source);
		}
		$network = SourceKey::tryFromIp(explode('/', $ban->getBanKey(), 2)[0]);
		return $network !== null && $network->family === 4 && $network->netKey === $ban->getBanKey() ? 'net:' . $network->netKey : null;
	}

	private static function toolKey(SourceKey $source): string {
		return 'tool:' . $source->ipKey;
	}

	private static function sourceKey(SourceKey $source): string {
		return 'ip:' . $source->ipKey;
	}

	private static function passwordKey(string $fingerprint): string {
		return 'fp:' . $fingerprint;
	}
}
