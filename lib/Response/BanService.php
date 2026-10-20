<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Response;

use OCA\IntrusionDetection\Address\AddressCache;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\Ban;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Db\LoginMapper;
use OCA\IntrusionDetection\Event\BanCreatedEvent;
use OCA\IntrusionDetection\Event\BanLiftedEvent;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\SourceKey;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\Security\ISecureRandom;

/**
 * Blocks addresses and networks for hours, escalating for repeat offenders.
 *
 * - Level: none before within the history window gives level 1, one gives 2,
 *   more give 3; the durations come from the settings.
 * - IPv4 addresses are blocked singly; once BAN_NET_AFTER addresses of one /24
 *   are blocked within 24 hours, the /24 is blocked too. IPv6 is always
 *   blocked as a /64.
 * - Safety valve: an address (or network) from which BAN_SHARED_IP_USERS or
 *   more different people logged in within 24 hours is not blocked.
 * - Loopback, the server's own address and the brute-force allowlist are never blocked.
 */
class BanService {
	/** References avoid characters that are easily confused: no 0, O, 1, I or l */
	public const REFERENCE_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

	public function __construct(
		private readonly BanMapper $mapper,
		private readonly LoginMapper $loginMapper,
		private readonly Settings $settings,
		private readonly AddressCache $addressCache,
		private readonly RemoteAddressResolver $addresses,
		private readonly ITimeFactory $timeFactory,
		private readonly ISecureRandom $random,
		private readonly IEventDispatcher $dispatcher,
	) {
	}

	public function ban(
		SourceKey $source,
		string $checkId,
		?int $detectionId = null,
		?int $forceLevel = null,
		bool $skipSafetyValve = false,
	): BanResult {
		if ($this->addresses->isNeverBlocked($source)) {
			return new BanResult(BanResult::SKIPPED_NEVER);
		}
		if ($this->addresses->isBypassListed($source)) {
			return new BanResult(BanResult::SKIPPED_BYPASS);
		}
		$now = $this->timeFactory->getTime();

		if (!$skipSafetyValve) {
			$shared = $this->sharedUsers($source, $now);
			if ($shared > 0) {
				return new BanResult(BanResult::SKIPPED_SHARED, sharedUsers: $shared);
			}
		}

		$scope = $source->family === 6 ? Ban::SCOPE_NET : Ban::SCOPE_IP;
		$banKey = $scope === Ban::SCOPE_NET ? $source->netKey : $source->ipKey;
		$cidr = $scope === Ban::SCOPE_NET ? $source->netKey : $source->ip . '/32';
		$existing = $this->activeFor($banKey, $now);
		if ($existing !== null) {
			// The active ban is not an earlier offence: another check of the same
			// attack must not escalate it. Only a stronger reason (e.g. a decoy
			// after a trap hit) raises the level.
			$level = $forceLevel === null ? 0 : min(3, $forceLevel);
			if ($existing->getLevel() >= $level) {
				return new BanResult(BanResult::ALREADY, $existing);
			}
			$existing->setLevel($level);
			$existing->setExpiresAt(max($existing->getExpiresAt(), $now + $this->durationFor($level)));
			$this->mapper->update($existing);
			$this->changed($existing, true);
			return new BanResult(BanResult::EXTENDED, $existing);
		}

		$level = $this->levelFor($banKey, $now, $forceLevel);

		$ban = $this->insert($cidr, $scope, $banKey, $level, $checkId, $detectionId, $now, $now + $this->durationFor($level));
		$netBan = $scope === Ban::SCOPE_IP ? $this->escalateToNetwork($source, $checkId, $detectionId, $now) : null;
		return new BanResult(BanResult::BANNED, $ban, $netBan);
	}

	/**
	 * Block an address or network by hand. Accepts an IPv4 address, an IPv4
	 * /24, or an IPv6 address or /64 (stored as the /64). Manual blocks skip
	 * the safety valve: the administrator decided.
	 *
	 * @throws \InvalidArgumentException for anything else
	 */
	public function banManually(string $target, int $level, string $actor, ?string $note, ?int $duration = null): Ban {
		$now = $this->timeFactory->getTime();
		[$cidr, $scope, $banKey] = $this->parseTarget($target);
		$level = max(1, min(3, $level));
		$expires = $now + ($duration ?? $this->durationFor($level));
		$existing = $this->activeFor($banKey, $now);
		if ($existing !== null) {
			$existing->setLevel(max($existing->getLevel(), $level));
			$existing->setExpiresAt(max($existing->getExpiresAt(), $expires));
			$existing->setNote($note ?? $existing->getNote());
			$this->mapper->update($existing);
			$this->changed($existing, true);
			return $existing;
		}
		$ban = $this->insert($cidr, $scope, $banKey, $level, 'manual', null, $now, $expires, $actor, $note);
		return $ban;
	}

	public function lift(Ban $ban, string $actor, string $note): void {
		if ($ban->getLiftedAt() !== null) {
			return;
		}
		$ban->setLiftedAt($this->timeFactory->getTime());
		$ban->setLiftedBy($actor);
		$ban->setLiftNote(mb_substr($note, 0, 255));
		$this->mapper->update($ban);
		$this->addressCache->bump();
		$this->dispatcher->dispatchTyped(new BanLiftedEvent($ban));
	}

	/**
	 * Duration in seconds of a ban at the given level.
	 */
	public function durationFor(int $level): int {
		$durations = $this->settings->banDurations();
		return $durations[max(1, min(3, $level))];
	}

	/**
	 * How many people logged in successfully from the address, or its
	 * network, in the last 24 hours, if that reaches the safety valve's
	 * threshold; 0 otherwise.
	 */
	public function sharedUsers(SourceKey $source, int $now): int {
		$threshold = $this->settings->getInt(GlobalSettings::BAN_SHARED_IP_USERS);
		if ($threshold <= 0) {
			return 0;
		}
		$sinceHour = intdiv($now - 86400, 3600);
		$users = max(
			$this->loginMapper->distinctUsersForIp($source->ipKey, $sinceHour),
			$source->netKey !== $source->ipKey ? $this->loginMapper->distinctUsersForNet($source->netKey, $sinceHour) : 0,
		);
		return $users >= $threshold ? $users : 0;
	}

	private function levelFor(string $banKey, int $now, ?int $forceLevel): int {
		$historyDays = $this->settings->getInt(GlobalSettings::BAN_HISTORY_DAYS);
		$earlier = $this->mapper->countSince($banKey, $now - $historyDays * 86400);
		$level = match (true) {
			$earlier === 0 => 1,
			$earlier === 1 => 2,
			default => 3,
		};
		return max($level, min(3, $forceLevel ?? 1));
	}

	private function activeFor(string $banKey, int $now): ?Ban {
		$active = $this->mapper->findActiveForKeys([$banKey], $now);
		usort($active, static fn (Ban $a, Ban $b): int => $b->getExpiresAt() <=> $a->getExpiresAt());
		return $active[0] ?? null;
	}

	/**
	 * Block the /24 once enough of its addresses are blocked.
	 */
	private function escalateToNetwork(SourceKey $source, string $checkId, ?int $detectionId, int $now): ?Ban {
		$netAfter = $this->settings->getInt(GlobalSettings::BAN_NET_AFTER);
		$prefix = substr($source->netKey, 0, (int)strrpos($source->netKey, '.') + 1);
		$banned = $this->mapper->findActiveInNet($prefix, $now - 86400, $now);
		if (count($banned) < $netAfter || $this->activeFor($source->netKey, $now) !== null) {
			return null;
		}
		$level = max(array_map(static fn (Ban $b): int => $b->getLevel(), $banned));
		return $this->insert($source->netKey, Ban::SCOPE_NET, $source->netKey, $level, $checkId, $detectionId, $now, $now + $this->durationFor($level));
	}

	private function insert(
		string $cidr,
		string $scope,
		string $banKey,
		int $level,
		string $checkId,
		?int $detectionId,
		int $now,
		int $expiresAt,
		?string $createdBy = null,
		?string $note = null,
	): Ban {
		$ban = new Ban();
		$ban->setReference($this->newReference());
		$ban->setCidr($cidr);
		$ban->setScope($scope);
		$ban->setBanKey($banKey);
		$ban->setLevel($level);
		$ban->setCheckId($checkId);
		$ban->setDetectionId($detectionId);
		$ban->setCreatedBy($createdBy);
		$ban->setNote($note === null ? null : mb_substr($note, 0, 255));
		$ban->setCreatedAt($now);
		$ban->setExpiresAt($expiresAt);
		$ban = $this->mapper->insert($ban);
		$this->changed($ban, false);
		return $ban;
	}

	private function changed(Ban $ban, bool $updated): void {
		$this->addressCache->bump();
		$this->dispatcher->dispatchTyped(new BanCreatedEvent($ban, $updated));
	}

	private function newReference(): string {
		do {
			$reference = $this->random->generate(8, self::REFERENCE_CHARS);
		} while ($this->mapper->referenceExists($reference));
		return $reference;
	}

	/**
	 * @return array{0: string, 1: string, 2: string} cidr, scope and ban key
	 */
	private function parseTarget(string $target): array {
		$target = trim($target);
		$prefixLength = null;
		if (str_contains($target, '/')) {
			[$target, $length] = explode('/', $target, 2);
			if (!ctype_digit($length)) {
				throw new \InvalidArgumentException('Invalid prefix length');
			}
			$prefixLength = (int)$length;
		}
		$source = SourceKey::fromIp($target);
		if ($source->family === 6) {
			if ($prefixLength !== null && $prefixLength !== 64 && $prefixLength !== 128) {
				throw new \InvalidArgumentException('IPv6 blocks cover a /64');
			}
			return [$source->netKey, Ban::SCOPE_NET, $source->netKey];
		}
		if ($prefixLength === 24) {
			return [$source->netKey, Ban::SCOPE_NET, $source->netKey];
		}
		if ($prefixLength !== null && $prefixLength !== 32) {
			throw new \InvalidArgumentException('IPv4 blocks cover one address or a /24');
		}
		return [$source->ip . '/32', Ban::SCOPE_IP, $source->ipKey];
	}
}
