<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\TokenConcurrentUse;

use OCA\IntrusionDetection\Net\SourceKey;

/**
 * Where one credential was used lately, as kept in its memory-cache entry
 * (concept section 10.12), and the switching rule.
 *
 * - Visits: the last up to MAX_VISITS runs of requests from one network
 *   (/24 for IPv4, /64 for IPv6), each with its first and last use and the
 *   latest address. Consecutive requests from the same network are one visit.
 * - IPv4 and IPv6 are separate streams: a device that alternates between
 *   its IPv4 and IPv6 addresses never switches. A switch is a new visit
 *   from another network of the same family as the newest visit of that
 *   family.
 * - Per family, the times of the switches back and forth between the same
 *   two networks (A, B, A, B). A switch to a third network starts over, so
 *   a phone that moves from Wi-Fi to mobile data switches once and stays.
 *
 * The credential switched networks "at the same time" when there were at
 * least `min_switches` such switches within `window`. It then fires at most
 * once per window.
 */
final class CredentialHistory {
	public const MAX_VISITS = 4;
	/** The most switches kept per family: the largest `min_switches` */
	public const MAX_SWITCHES = 20;
	/** A visit's last use is refreshed (one cache write) at most this often */
	public const REFRESH = 300;

	/**
	 * @param list<array{0: string, 1: int, 2: int, 3: int, 4: string, 5: string}> $visits net key, family, first use, last use, address, user tag
	 * @param array<int, array{0: string, 1: string, 2: list<int>}> $runs per family: the two networks and the times of the switches between them
	 */
	private function __construct(
		private array $visits,
		private array $runs,
		private int $firedAt,
	) {
	}

	public static function empty(): self {
		return new self([], [], 0);
	}

	/**
	 * Reads a cache value. Anything malformed counts as no history.
	 */
	public static function fromCache(mixed $value): self {
		if (!is_array($value)) {
			return self::empty();
		}
		$visits = [];
		foreach (is_array($value['v'] ?? null) ? $value['v'] : [] as $visit) {
			if (!is_array($visit) || count($visit) !== 6) {
				continue;
			}
			[$net, $family, $first, $last, $ip, $tag] = array_values($visit);
			if (is_string($net) && is_int($family) && is_int($first) && is_int($last) && is_string($ip) && is_string($tag)) {
				$visits[] = [$net, $family, $first, $last, $ip, $tag];
			}
		}
		$runs = [];
		foreach (is_array($value['r'] ?? null) ? $value['r'] : [] as $family => $run) {
			if (($family === 4 || $family === 6) && is_array($run) && is_string($run[0] ?? null) && is_string($run[1] ?? null) && is_array($run[2] ?? null)) {
				$runs[$family] = [$run[0], $run[1], array_values(array_filter($run[2], 'is_int'))];
			}
		}
		return new self(array_slice($visits, -self::MAX_VISITS), $runs, is_int($value['f'] ?? null) ? $value['f'] : 0);
	}

	/**
	 * @return array{v: list<array{0: string, 1: int, 2: int, 3: int, 4: string, 5: string}>, r: array<int, array{0: string, 1: string, 2: list<int>}>, f: int}
	 */
	public function toCache(): array {
		return ['v' => $this->visits, 'r' => $this->runs, 'f' => $this->firedAt];
	}

	public function isEmpty(): bool {
		return $this->visits === [];
	}

	/**
	 * The common case: the request comes from the network of the newest
	 * visit of its family, which was refreshed less than REFRESH seconds
	 * ago. Nothing needs to be written.
	 */
	public function isCurrent(SourceKey $source, int $now): bool {
		$newest = $this->newestOf($source->family);
		return $newest !== null
			&& $this->visits[$newest][0] === $source->netKey
			&& $now - $this->visits[$newest][3] < self::REFRESH;
	}

	/**
	 * Record a use that is not the common case.
	 *
	 * @param string $userTag see {@see PresentedCredential::userTag()}
	 * @param \Closure(): array{0: int, 1: int} $thresholds `window` and `min_switches`, read only when the use is a switch
	 * @return ?CredentialSwitch the switch when it fires
	 */
	public function record(SourceKey $source, string $userTag, int $now, \Closure $thresholds): ?CredentialSwitch {
		$newest = $this->newestOf($source->family);
		if ($newest !== null && $this->visits[$newest][0] === $source->netKey) {
			$this->visits[$newest][3] = $now;
			$this->visits[$newest][4] = $source->ip;
			return null;
		}
		$previous = $newest === null ? null : $this->visits[$newest];
		$this->visits[] = [$source->netKey, $source->family, $now, $now, $source->ip, $userTag];
		$this->trimVisits();
		// Two accounts that share a password are not one credential.
		if ($previous === null || ($previous[5] !== '' && $userTag !== '' && $previous[5] !== $userTag)) {
			return null;
		}

		[$window, $minSwitches] = $thresholds();
		$run = $this->runs[$source->family] ?? null;
		$sameTwo = $run !== null
			&& (($run[0] === $previous[0] && $run[1] === $source->netKey) || ($run[1] === $previous[0] && $run[0] === $source->netKey));
		$times = $sameTwo ? $run[2] : [];
		$times[] = $now;
		$times = array_values(array_filter($times, static fn (int $t): bool => $t > $now - $window));
		$times = array_slice($times, -self::MAX_SWITCHES);
		$this->runs[$source->family] = [$previous[0], $source->netKey, $times];

		if (count($times) < $minSwitches || $now - $this->firedAt < $window) {
			return null;
		}
		$this->firedAt = $now;
		return new CredentialSwitch(
			otherIp: $previous[4],
			otherNet: $previous[0],
			currentIp: $source->ip,
			currentNet: $source->netKey,
			family: $source->family,
			switches: count($times),
			firstSwitchAt: $times[0],
			at: $now,
		);
	}

	private function newestOf(int $family): ?int {
		for ($i = count($this->visits) - 1; $i >= 0; $i--) {
			if ($this->visits[$i][1] === $family) {
				return $i;
			}
		}
		return null;
	}

	/**
	 * Drops the oldest visits beyond MAX_VISITS, but keeps the newest visit
	 * of each family: it is what the next request is compared with.
	 */
	private function trimVisits(): void {
		while (count($this->visits) > self::MAX_VISITS) {
			foreach ($this->visits as $i => $visit) {
				if ($this->newestOf($visit[1]) !== $i) {
					array_splice($this->visits, $i, 1);
					continue 2;
				}
			}
			return;
		}
	}
}
