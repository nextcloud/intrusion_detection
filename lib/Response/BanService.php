<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Response;

use OCA\IntrusionDetection\Address\AddressCache;
use OCA\IntrusionDetection\Address\AddressResolver;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Cache\KeyLock;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Db\Ban;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Db\IPurges;
use OCA\IntrusionDetection\Db\KeyMatch;
use OCA\IntrusionDetection\Event\TypedEvents;
use OCA\IntrusionDetection\Net\Ipv6Networks;
use OCA\IntrusionDetection\Net\ProtectedRanges;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\State\AppState;
use OCP\AppFramework\Db\DoesNotExistException;
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
 *   shared addresses, an unconfigured reverse proxy and the addresses of
 *   this server's own people ({@see BanExemptions}).
 * - The check for an active block and the insert run under a lock per
 *   address or network, so parallel requests create one block, not several.
 *   An address that is blocked already (also by a block of its network), or
 *   exempt, and a network far from its threshold, take no lock at all.
 * - Blocking many addresses at once ({@see banMany()}) costs one query for
 *   those blocked already, one escalation per network and one change of the
 *   cached verdicts.
 * - Ended blocks are kept for escalation: BAN_HISTORY, or longer when the
 *   history setting says so. Before they go, the addresses of the blocks
 *   that ended since the last cleanup are flagged ({@see purge()}).
 */
class BanService implements IPurges {
	/** References avoid characters that are easily confused: no 0, O, 1, I or l */
	public const REFERENCE_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
	/** The shortest block by hand */
	public const MIN_DURATION = 300;
	/** The longest block by hand */
	public const MAX_DURATION = 90 * 86400;
	/** The longest note of a block or a lift */
	public const MAX_NOTE = 255;
	/** With a distributed cache, up to this many changed addresses get a new verdict each; more drop all verdicts at once */
	public const REFRESH_MAX = 10;
	/** Blocks that ended up to this time have been flagged */
	public const BANS_FLAGGED_STATE = 'bans_flagged_until';
	/** Ended blocks are kept this long at least, for escalation */
	public const BAN_HISTORY = 30 * 86400;
	/** Ended blocks flagged per cleanup at most */
	public const ENDED_BANS_PER_RUN = 1000;
	/** Ban keys per query, below every database's limit for a list */
	private const KEYS_PER_QUERY = 500;

	/** @var list<Ban>|null bans whose cached verdicts change at the end of the batch, while one runs */
	private ?array $changes = null;

	public function __construct(
		private readonly BanMapper $mapper,
		private readonly BanExemptions $exemptions,
		private readonly AppSettings $settings,
		private readonly AddressCache $addressCache,
		private readonly AddressResolver $resolver,
		private readonly RemoteAddressResolver $addresses,
		private readonly ProtectedRanges $protected,
		private readonly FlaggedSources $flags,
		private readonly KeyLock $locks,
		private readonly ITimeFactory $timeFactory,
		private readonly ISecureRandom $random,
		private readonly TypedEvents $events,
		private readonly AppState $state,
		private readonly AuditLogger $audit,
	) {
	}

	/**
	 * Flag the addresses of the blocks that ended since the last cleanup,
	 * then delete the blocks that ended longer ago than their history.
	 */
	#[\Override]
	public function purge(int $now): int {
		$this->flagEndedBans($now);
		return $this->mapper->deleteEndedBefore($now - max(self::BAN_HISTORY, $this->settings->banHistoryDays() * 86400));
	}

	/**
	 * @param ?string $uid the account the detection is about, for the exemptions of checks about one account
	 */
	public function ban(SourceKey $source, string $checkId, ?string $detectionId = null, ?int $forceLevel = null, ?string $uid = null): BanResult {
		return $this->banMany([$source], $checkId, $detectionId, $forceLevel, $uid)[$source->ipKey];
	}

	/**
	 * Block several addresses for one detection, such as the addresses of a
	 * password spray: one query finds those that are blocked already (also
	 * by a block of their network), each network is escalated once, and the
	 * cached verdicts are changed once at the end.
	 *
	 * @param list<SourceKey> $sources
	 * @param ?string $uid the account the detection is about, for the exemptions of checks about one account
	 * @return array<string, BanResult> by ip key; a network block by escalation is in the result of the address that caused it
	 */
	public function banMany(array $sources, string $checkId, ?string $detectionId = null, ?int $forceLevel = null, ?string $uid = null): array {
		$results = [];
		$candidates = [];
		foreach ($sources as $source) {
			$results[$source->ipKey] = match (true) {
				$this->addresses->isNeverBlocked($source) => new BanResult(BanResult::SKIPPED_NEVER),
				$this->addresses->isBypassListed($source) => new BanResult(BanResult::SKIPPED_BYPASS),
				default => null,
			};
			if ($results[$source->ipKey] === null) {
				$candidates[$source->ipKey] = $source;
			}
		}
		if ($candidates === []) {
			return array_filter($results);
		}
		$now = $this->timeFactory->getTime();
		$active = $this->activeByKey($candidates, $now);
		// The active ban is not an earlier offence: another check of the same
		// attack must not escalate it. Only a stronger reason (e.g. a decoy
		// after a trap hit) raises the level.
		$level = $forceLevel === null ? 0 : min(3, $forceLevel);
		return $this->batch(function () use ($results, $candidates, $active, $level, $checkId, $detectionId, $forceLevel, $uid, $now): array {
			/** @var array<string, SourceKey> $escalate network => the last address of it that was blocked */
			$escalate = [];
			foreach ($candidates as $ipKey => $source) {
				$covering = null;
				foreach (AddressResolver::banKeys($source) as $key) {
					$ban = $active[$key] ?? null;
					if ($ban !== null && ($covering === null || $ban->getExpiresAt() > $covering->getExpiresAt())) {
						$covering = $ban;
					}
				}
				if ($covering !== null && $covering->getLevel() >= $level) {
					// Blocked already, by its own block or one of its network: no lock, no write.
					$results[$ipKey] = new BanResult(BanResult::ALREADY, $covering);
					continue;
				}
				if (!isset($active[$ipKey])) {
					$exempt = $this->exemptions->forAddress($source, $now, $checkId, $uid);
					if ($exempt !== null) {
						$results[$ipKey] = $exempt;
						continue;
					}
				}
				$results[$ipKey] = $this->banLocked($source, $checkId, $detectionId, $forceLevel, $level, $now);
				if ($results[$ipKey]->outcome === BanResult::BANNED) {
					$escalate[$source->family === 4 ? $source->netKey : Ipv6Networks::key($source, 56)] = $source;
				}
			}
			foreach ($escalate as $source) {
				$netBan = $this->escalate($source, $checkId, $detectionId, $uid, $now);
				$result = $results[$source->ipKey];
				if ($netBan !== null && $result !== null) {
					$results[$source->ipKey] = new BanResult(BanResult::BANNED, $result->ban, $netBan);
				}
			}
			return array_filter($results);
		});
	}

	/**
	 * Run work that may block, raise or lift many addresses, and change the
	 * cached verdicts once at its end ({@see flush()}). Nested calls join the
	 * outer one.
	 *
	 * @template T
	 * @param \Closure(): T $work
	 * @return T
	 */
	public function batch(\Closure $work): mixed {
		if ($this->changes !== null) {
			return $work();
		}
		$this->changes = [];
		try {
			return $work();
		} finally {
			$changes = $this->changes;
			$this->changes = null;
			$this->flush($changes);
		}
	}

	/**
	 * Block the IPv4 /24 of an address as a whole, for a network rule whose
	 * addresses each did too little to be blocked alone. The same safety
	 * rules as for a network block by escalation apply: never over
	 * loopback, the server or the allowlist, and never a network many
	 * people, a reverse proxy or an administrator log in from.
	 *
	 * @param ?string $uid the account the detection is about, for the exemptions of checks about one account
	 */
	public function banNetwork(SourceKey $member, string $checkId, ?string $detectionId = null, ?string $uid = null): BanResult {
		if ($member->family !== 4) {
			return new BanResult(BanResult::SKIPPED_NEVER);
		}
		$netKey = $member->netKey;
		$now = $this->timeFactory->getTime();
		$existing = $this->activeFor([$netKey], $now);
		if ($existing !== null) {
			return new BanResult(BanResult::ALREADY, $existing);
		}
		return $this->locks->run('ban', $netKey, function () use ($netKey, $checkId, $detectionId, $uid, $now): BanResult {
			$existing = $this->activeFor([$netKey], $now);
			if ($existing !== null) {
				return new BanResult(BanResult::ALREADY, $existing);
			}
			$exempt = $this->exemptions->forNetwork($netKey, new KeyMatch([$netKey]), $now, $checkId, $uid);
			if ($exempt !== null) {
				return $exempt;
			}
			$level = $this->levelFor($netKey, $now, null);
			return new BanResult(BanResult::BANNED, $this->insert($netKey, Ban::SCOPE_NET, $netKey, $level, $checkId, $detectionId, $now, $now + $this->durationFor($level)));
		});
	}

	/**
	 * Whether a block of this address that was held back (a shared address,
	 * a reverse proxy) should be reported now, see {@see BanExemptions::firstReport()}.
	 */
	public function firstReport(SourceKey $source): bool {
		return $this->exemptions->firstReport($source);
	}

	/**
	 * Block an address or network by hand, and write it to the audit log.
	 * Accepts an IPv4 address, an IPv4 /24, or an IPv6 address or /64
	 * (stored as the /64). Manual blocks skip the safety valve: the
	 * administrator decided. Loopback, the server's own address and the
	 * brute-force allowlist are refused, also inside a /24, and so is the
	 * address of the administrator who asks, where there is one.
	 *
	 * @param int $level 1 to 3, which sets the duration
	 * @param ?int $duration MIN_DURATION to MAX_DURATION seconds instead of the level's
	 * @param ?string $note at most MAX_NOTE characters
	 * @throws InvalidBanException
	 */
	public function banManually(string $target, int $level, string $actor, ?string $note, ?int $duration = null): Ban {
		$target = trim($target);
		if ($level < 1 || $level > 3) {
			throw new InvalidBanException(InvalidBanException::LEVEL);
		}
		if ($duration !== null && ($duration < self::MIN_DURATION || $duration > self::MAX_DURATION)) {
			throw new InvalidBanException(InvalidBanException::DURATION);
		}
		$note = self::note($note);
		$this->refuseTarget($target);
		$now = $this->timeFactory->getTime();
		[$cidr, $scope, $banKey] = $this->parseTarget($target);
		$source = SourceKey::fromIp(explode('/', $cidr, 2)[0]);
		if ($this->addresses->isIgnored($source) || $this->protected->overlapsCidr($cidr)) {
			throw new InvalidBanException(InvalidBanException::CONTAINS_NEVER, $cidr);
		}
		$expires = $now + ($duration ?? $this->durationFor($level));
		$ban = $this->locks->run('ban', $banKey, function () use ($cidr, $scope, $banKey, $level, $actor, $note, $now, $expires): Ban {
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
		$this->audit->log('block %s (%s) added by %s: %s', ['reference' => $ban->getDisplayReference(), 'cidr' => $ban->getCidr(), 'actor' => $actor, 'note' => $note]);
		return $ban;
	}

	/**
	 * Lift a block by its id, see {@see lift()}.
	 *
	 * @throws InvalidBanException for a note that is too long, before the block is looked up
	 * @throws DoesNotExistException
	 */
	public function liftById(string $id, string $actor, string $note): Ban {
		self::note($note);
		$ban = $this->mapper->findById($id);
		$this->lift($ban, $actor, $note);
		return $ban;
	}

	/**
	 * Lift a block, and write it to the audit log. A block that was lifted
	 * already stays as it is.
	 *
	 * @param string $note why, at most MAX_NOTE characters
	 * @throws InvalidBanException for a note that is too long
	 */
	public function lift(Ban $ban, string $actor, string $note): void {
		$note = (string)self::note($note);
		if ($ban->getLiftedAt() !== null) {
			return;
		}
		$ban->setLiftedAt($this->timeFactory->getTime());
		$ban->setLiftedBy($actor);
		$ban->setLiftNote($note);
		$this->mapper->update($ban);
		$this->flags->unflagBan($ban);
		$this->invalidate($ban);
		$this->events->banLifted($ban);
		$this->audit->log('block %s (%s) lifted by %s: %s', ['reference' => $ban->getDisplayReference(), 'cidr' => $ban->getCidr(), 'actor' => $actor, 'note' => $note]);
	}

	/**
	 * The limits of a block by hand, and the durations of the levels.
	 *
	 * @return array{minDuration: int, maxDuration: int, maxNote: int, levelDurations: list<int>}
	 */
	public function limits(): array {
		return [
			'minDuration' => self::MIN_DURATION,
			'maxDuration' => self::MAX_DURATION,
			'maxNote' => self::MAX_NOTE,
			'levelDurations' => [$this->durationFor(1), $this->durationFor(2), $this->durationFor(3)],
		];
	}

	/**
	 * Duration in seconds of a ban at the given level.
	 */
	public function durationFor(int $level): int {
		$durations = $this->settings->banDurations();
		return $durations[max(1, min(3, $level))];
	}

	/**
	 * Block one address under its lock, or raise its own active block.
	 */
	private function banLocked(SourceKey $source, string $checkId, ?string $detectionId, ?int $forceLevel, int $level, int $now): BanResult {
		$scope = $source->family === 6 ? Ban::SCOPE_NET : Ban::SCOPE_IP;
		$cidr = $scope === Ban::SCOPE_NET ? $source->ipKey : $source->ip . '/32';
		return $this->locks->run('ban', $source->ipKey, function () use ($source, $scope, $cidr, $checkId, $detectionId, $forceLevel, $level, $now): BanResult {
			$existing = $this->activeFor([$source->ipKey], $now);
			if ($existing !== null) {
				if ($existing->getLevel() >= $level) {
					return new BanResult(BanResult::ALREADY, $existing);
				}
				$existing->setLevel($level);
				$existing->setExpiresAt(max($existing->getExpiresAt(), $now + $this->durationFor($level)));
				$this->mapper->update($existing);
				$this->changed($existing, true);
				return new BanResult(BanResult::EXTENDED, $existing);
			}
			$newLevel = $this->levelFor($source->ipKey, $now, $forceLevel);
			return new BanResult(BanResult::BANNED, $this->insert($cidr, $scope, $source->ipKey, $newLevel, $checkId, $detectionId, $now, $now + $this->durationFor($newLevel)));
		});
	}

	/**
	 * The active bans of the addresses and of the networks around them, the
	 * longest of each key, in chunks that every database accepts.
	 *
	 * @param array<string, SourceKey> $sources
	 * @return array<string, Ban> by ban key
	 */
	private function activeByKey(array $sources, int $now): array {
		$keys = [];
		foreach ($sources as $source) {
			foreach (AddressResolver::banKeys($source) as $key) {
				$keys[$key] = true;
			}
		}
		$active = [];
		foreach (array_chunk(array_keys($keys), self::KEYS_PER_QUERY) as $chunk) {
			foreach ($this->mapper->findActiveForKeys($chunk, $now) as $ban) {
				$key = $ban->getBanKey();
				if (!isset($active[$key]) || $ban->getExpiresAt() > $active[$key]->getExpiresAt()) {
					$active[$key] = $ban;
				}
			}
		}
		return $active;
	}

	private function levelFor(string $banKey, int $now, ?int $forceLevel): int {
		$historyDays = $this->settings->banHistoryDays();
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
	private function escalate(SourceKey $source, string $checkId, ?string $detectionId, ?string $uid, int $now): ?Ban {
		$netAfter = $this->settings->banNetAfter();
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
			$in48 = KeyMatch::slash64sIn($key48);
			$in56 = KeyMatch::slash64sIn($key56);
			$candidates = [
				[$key48, $in48, $in48, $netAfter * $netAfter, [$key48]],
				[$key56, $in56, $in56, $netAfter, [$key56, $key48]],
			];
		}
		foreach ($candidates as [$netKey, $members, $loginKeys, $threshold, $covering]) {
			// Most blocks are far from a network block: decided without the lock, checked again under it.
			if (count($this->mapper->activeKeysIn($members, $now - 86400, $now)) < $threshold || $this->activeFor($covering, $now) !== null) {
				continue;
			}
			$ban = $this->locks->run('ban', $netKey, function () use ($netKey, $members, $loginKeys, $threshold, $covering, $checkId, $detectionId, $uid, $now): ?Ban {
				$blocked = $this->mapper->activeKeysIn($members, $now - 86400, $now);
				if (count($blocked) < $threshold || $this->activeFor($covering, $now) !== null
					|| $this->exemptions->forNetwork($netKey, $loginKeys, $now, $checkId, $uid) !== null) {
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
		?string $detectionId,
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
		$ban->setCreatedTime($now);
		$ban->setExpiresAt($expiresAt);
		$ban = $this->mapper->insert($ban);
		$this->changed($ban, false);
		return $ban;
	}

	private function changed(Ban $ban, bool $updated): void {
		$this->invalidate($ban);
		$this->events->banCreated($ban, $updated);
	}

	private function invalidate(Ban $ban): void {
		if ($this->changes !== null) {
			$this->changes[] = $ban;
			return;
		}
		$this->flush([$ban]);
	}

	/**
	 * Update the cached verdicts that changed bans change: with a
	 * distributed cache that of each address (an IPv6 /64), for up to
	 * REFRESH_MAX of them; otherwise, and for networks, all verdicts at
	 * once, with one new version.
	 *
	 * @param list<Ban> $bans
	 */
	private function flush(array $bans): void {
		if ($bans === []) {
			return;
		}
		$sources = [];
		foreach ($bans as $ban) {
			$sources[] = SourceKey::tryFromIpKey($ban->getBanKey());
		}
		if (!$this->addressCache->isDistributed() || count($sources) > self::REFRESH_MAX || in_array(null, $sources, true)) {
			$this->addressCache->bump();
			return;
		}
		$now = $this->timeFactory->getTime();
		foreach ($sources as $source) {
			$this->addressCache->refresh($source, $this->resolver->resolve($source), $now);
		}
	}

	private function newReference(): string {
		do {
			$reference = $this->random->generate(8, self::REFERENCE_CHARS);
		} while ($this->mapper->referenceExists($reference));
		return $reference;
	}

	/**
	 * The note trimmed, null when empty.
	 *
	 * @throws InvalidBanException for a note that is too long
	 */
	private static function note(?string $note): ?string {
		$note = trim($note ?? '');
		if (mb_strlen($note) > self::MAX_NOTE) {
			throw new InvalidBanException(InvalidBanException::NOTE_TOO_LONG);
		}
		return $note === '' ? null : $note;
	}

	/**
	 * Refuses a target that is no address, that is never blocked, or that
	 * is the address of the administrator who asks or its network.
	 *
	 * @throws InvalidBanException
	 */
	private function refuseTarget(string $target): void {
		$parts = explode('/', $target, 2);
		$source = SourceKey::tryFromIp($parts[0]);
		if ($source === null || (isset($parts[1]) && !ctype_digit($parts[1]))) {
			throw new InvalidBanException(InvalidBanException::TARGET);
		}
		if ($this->addresses->isNeverBlocked($source)) {
			throw new InvalidBanException(InvalidBanException::NEVER, $source->ip);
		}
		if ($this->addresses->isBypassListed($source)) {
			throw new InvalidBanException(InvalidBanException::ALLOWLISTED, $source->ip);
		}
		$own = $this->addresses->current();
		$wholeNetwork = $source->family === 6 || ($parts[1] ?? '') === '24';
		if ($own !== null && ($wholeNetwork ? $own->sameNetwork($source) : $own->ipKey === $source->ipKey)) {
			throw new InvalidBanException(InvalidBanException::OWN_ADDRESS, $own->ip);
		}
	}

	/**
	 * @return array{0: string, 1: string, 2: string} cidr, scope and ban key
	 * @throws InvalidBanException
	 */
	private function parseTarget(string $target): array {
		$target = trim($target);
		$prefixLength = null;
		if (str_contains($target, '/')) {
			[$target, $length] = explode('/', $target, 2);
			if (!ctype_digit($length)) {
				throw new InvalidBanException(InvalidBanException::TARGET);
			}
			$prefixLength = (int)$length;
		}
		$source = SourceKey::tryFromIp($target) ?? throw new InvalidBanException(InvalidBanException::TARGET);
		if ($source->family === 6) {
			if ($prefixLength !== null && $prefixLength !== 64 && $prefixLength !== 128) {
				throw new InvalidBanException(InvalidBanException::TARGET);
			}
			return [$source->netKey, Ban::SCOPE_NET, $source->netKey];
		}
		if ($prefixLength === 24) {
			return [$source->netKey, Ban::SCOPE_NET, $source->netKey];
		}
		if ($prefixLength !== null && $prefixLength !== 32) {
			throw new InvalidBanException(InvalidBanException::TARGET);
		}
		return [$source->ip . '/32', Ban::SCOPE_IP, $source->ipKey];
	}

	/**
	 * Flag the addresses of blocks that ended since the last run. At most
	 * ENDED_BANS_PER_RUN per run; the rest follow at the next. Blocks that
	 * ended longer ago than a flag lasts are skipped: their flag would have
	 * ended too. The progress is only written when something ended.
	 */
	private function flagEndedBans(int $now): void {
		$since = max($this->state->getInt(self::BANS_FLAGGED_STATE), $now - FlaggedSources::DURATION);
		$ended = $this->mapper->findEndedBetween($since, $now, self::ENDED_BANS_PER_RUN);
		if ($ended === []) {
			return;
		}
		foreach ($ended as $ban) {
			$this->flags->flagEndedBan($ban);
		}
		// Blocks that end in the same second as the last one flagged are looked at again; flagging is idempotent.
		$this->state->setInt(self::BANS_FLAGGED_STATE, count($ended) < self::ENDED_BANS_PER_RUN ? $now : $ended[count($ended) - 1]->getExpiresAt() - 1);
	}
}
