<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Response;

use OCA\IntrusionDetection\Address\AddressCache;
use OCA\IntrusionDetection\Address\AddressResolver;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\Ban;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Db\KeyLock;
use OCA\IntrusionDetection\Db\KeyMatch;
use OCA\IntrusionDetection\Event\TypedEvents;
use OCA\IntrusionDetection\Net\Ipv6Networks;
use OCA\IntrusionDetection\Net\ProtectedRanges;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\SourceKey;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Security\ISecureRandom;

/**
 * Blocks addresses and networks for hours, escalating for repeat offenders.
 *
 * - Level: none before within the history window gives level 1, one gives 2,
 *   more give 3; the durations come from the settings.
 * - IPv4 addresses are blocked singly; once BAN_NET_AFTER addresses of one /24
 *   are blocked within 24 hours, the /24 is blocked too.
 * - IPv6 is blocked as a /64. Once BAN_NET_AFTER /64s of one /56 are blocked
 *   within 24 hours, the /56 is blocked; once BAN_NET_AFTER² /64s of one /48
 *   are, the /48 (an attacker who controls a whole /48 rarely hits one /56
 *   three times).
 * - Loopback, the server's own address and the brute-force allowlist are
 *   never blocked, not even inside a network. Automatic blocks also spare
 *   shared addresses and the addresses of this server's own people
 *   ({@see BanExemptions}).
 * - The check for an active block and the insert run under a lock per
 *   address or network, so parallel requests create one block, not several.
 */
class BanService {
	/** References avoid characters that are easily confused: no 0, O, 1, I or l */
	public const REFERENCE_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
	/** The longest block by hand */
	public const MAX_DURATION = 90 * 86400;
	/** Waiting for another request blocking the same address: tries and pause between them */

	public function __construct(
		private readonly BanMapper $mapper,
		private readonly BanExemptions $exemptions,
		private readonly Settings $settings,
		private readonly AddressCache $addressCache,
		private readonly AddressResolver $resolver,
		private readonly RemoteAddressResolver $addresses,
		private readonly ProtectedRanges $protected,
		private readonly FlaggedSources $flags,
		private readonly KeyLock $locks,
		private readonly ITimeFactory $timeFactory,
		private readonly ISecureRandom $random,
		private readonly TypedEvents $events,
	) {
	}

	public function ban(SourceKey $source, string $checkId, ?int $detectionId = null, ?int $forceLevel = null): BanResult {
		if ($this->addresses->isNeverBlocked($source)) {
			return new BanResult(BanResult::SKIPPED_NEVER);
		}
		if ($this->addresses->isBypassListed($source)) {
			return new BanResult(BanResult::SKIPPED_BYPASS);
		}
		$now = $this->timeFactory->getTime();
		$scope = $source->family === 6 ? Ban::SCOPE_NET : Ban::SCOPE_IP;
		$cidr = $scope === Ban::SCOPE_NET ? $source->ipKey : $source->ip . '/32';

		$result = $this->locks->run('ban', $source->ipKey, function () use ($source, $scope, $cidr, $checkId, $detectionId, $forceLevel, $now): BanResult {
			$existing = $this->activeFor([$source->ipKey], $now);
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
			$exempt = $this->exemptions->forAddress($source, $now);
			if ($exempt !== null) {
				return $exempt;
			}
			$level = $this->levelFor($source->ipKey, $now, $forceLevel);
			return new BanResult(BanResult::BANNED, $this->insert($cidr, $scope, $source->ipKey, $level, $checkId, $detectionId, $now, $now + $this->durationFor($level)));
		});
		if ($result->outcome !== BanResult::BANNED || $result->ban === null) {
			return $result;
		}
		return new BanResult(BanResult::BANNED, $result->ban, $this->escalate($source, $checkId, $detectionId, $now));
	}

	/**
	 * Block an address or network by hand. Accepts an IPv4 address, an IPv4
	 * /24, or an IPv6 address or /64 (stored as the /64). Manual blocks skip
	 * the safety valve: the administrator decided. Loopback, the server's own
	 * address and the brute-force allowlist are refused, also inside a /24.
	 *
	 * @throws BanRefusedException for a target that is never blocked
	 * @throws \InvalidArgumentException for anything else that is not a valid target
	 */
	public function banManually(string $target, int $level, string $actor, ?string $note, ?int $duration = null): Ban {
		$now = $this->timeFactory->getTime();
		[$cidr, $scope, $banKey] = $this->parseTarget($target);
		$source = SourceKey::fromIp(explode('/', $cidr, 2)[0]);
		if ($this->addresses->isIgnored($source) || $this->protected->overlapsCidr($cidr)) {
			throw new BanRefusedException($cidr);
		}
		$level = max(1, min(3, $level));
		$expires = $now + ($duration ?? $this->durationFor($level));
		return $this->locks->run('ban', $banKey, function () use ($cidr, $scope, $banKey, $level, $actor, $note, $now, $expires): Ban {
			$existing = $this->activeFor([$banKey], $now);
			if ($existing !== null) {
				$existing->setLevel(max($existing->getLevel(), $level));
				$existing->setExpiresAt(max($existing->getExpiresAt(), $expires));
				$existing->setNote($note ?? $existing->getNote());
				$this->mapper->update($existing);
				$this->changed($existing, true);
				return $existing;
			}
			return $this->insert($cidr, $scope, $banKey, $level, 'manual', null, $now, $expires, $actor, $note);
		});
	}

	public function lift(Ban $ban, string $actor, string $note): void {
		if ($ban->getLiftedAt() !== null) {
			return;
		}
		$ban->setLiftedAt($this->timeFactory->getTime());
		$ban->setLiftedBy($actor);
		$ban->setLiftNote(mb_substr($note, 0, 255));
		$this->mapper->update($ban);
		$this->flags->unflagBan($ban);
		$this->invalidate($ban);
		$this->events->banLifted($ban);
	}

	/**
	 * Duration in seconds of a ban at the given level.
	 */
	public function durationFor(int $level): int {
		$durations = $this->settings->banDurations();
		return $durations[max(1, min(3, $level))];
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

	/**
	 * @param list<string> $banKeys
	 */
	private function activeFor(array $banKeys, int $now): ?Ban {
		$active = $this->mapper->findActiveForKeys($banKeys, $now);
		usort($active, static fn (Ban $a, Ban $b): int => $b->getExpiresAt() <=> $a->getExpiresAt());
		return $active[0] ?? null;
	}

	/**
	 * Block the network once enough of its addresses are blocked: the /24
	 * for IPv4; the /48, else the /56, for IPv6.
	 */
	private function escalate(SourceKey $source, string $checkId, ?int $detectionId, int $now): ?Ban {
		$netAfter = $this->settings->getInt(GlobalSettings::BAN_NET_AFTER);
		if ($netAfter < 1) {
			return null;
		}
		if ($source->family === 4) {
			$prefix = substr($source->netKey, 0, (int)strrpos($source->netKey, '.') + 1);
			// The addresses of the /24: one to three digits after the prefix, never the /24 key itself.
			$addresses = new KeyMatch([], [$prefix . '_', $prefix . '__', $prefix . '___']);
			$candidates = [[$source->netKey, $addresses, new KeyMatch([$source->netKey]), $netAfter, [$source->netKey]]];
		} else {
			$key48 = Ipv6Networks::key($source, 48);
			$key56 = Ipv6Networks::key($source, 56);
			$in48 = Ipv6Networks::slash64Keys($key48);
			$in56 = Ipv6Networks::slash64Keys($key56);
			$candidates = [
				[$key48, $in48, $in48, $netAfter * $netAfter, [$key48]],
				[$key56, $in56, $in56, $netAfter, [$key56, $key48]],
			];
		}
		foreach ($candidates as [$netKey, $members, $loginKeys, $threshold, $covering]) {
			$ban = $this->locks->run('ban', $netKey, function () use ($netKey, $members, $loginKeys, $threshold, $covering, $checkId, $detectionId, $now): ?Ban {
				$blocked = $this->mapper->activeKeysIn($members, $now - 86400, $now);
				if (count($blocked) < $threshold || $this->activeFor($covering, $now) !== null
					|| $this->exemptions->forNetwork($netKey, $loginKeys, $now) !== null) {
					return null;
				}
				$level = max($blocked);
				return $this->insert($netKey, Ban::SCOPE_NET, $netKey, $level, $checkId, $detectionId, $now, $now + $this->durationFor($level));
			});
			if ($ban !== null) {
				return $ban;
			}
		}
		return null;
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
		$this->invalidate($ban);
		$this->events->banCreated($ban, $updated);
	}

	/**
	 * Update the cached verdicts a ban changes: that of its one address (an
	 * IPv6 /64) with a distributed cache, otherwise all of them.
	 */
	private function invalidate(Ban $ban): void {
		$source = SourceKey::tryFromIpKey($ban->getBanKey());
		if ($source !== null && $this->addressCache->isDistributed()) {
			$this->addressCache->refresh($source, $this->resolver->resolve($source), $this->timeFactory->getTime());
		} else {
			$this->addressCache->bump();
		}
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
