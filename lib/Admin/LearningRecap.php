<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Admin;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Config\UserKeys;
use OCA\IntrusionDetection\Db\KeyMatch;
use OCA\IntrusionDetection\Db\StatsMapper;
use OCA\IntrusionDetection\Definition\Category;
use OCA\IntrusionDetection\Learning\LearningService;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCA\IntrusionDetection\State\AppState;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Config\IUserConfig;
use OCP\IL10N;
use OCP\IUserManager;

/**
 * The recap of the learning period that ended last, on the overview of the
 * admin page, from what the app keeps anyway:
 *
 * - attempts: the hits of the detections of attack checks (all but those
 *   Nextcloud raises itself and administration changes) created in the
 *   period, and their different addresses;
 * - the top attack: the attack check with the most hits;
 * - would have blocked: the addresses of detections that learning mode
 *   held back and whose block was not carried out
 *   ({@see StatsMapper::heldBackByLearning()});
 * - own people: the accounts with an accepted login (not refused or left
 *   unconfirmed) in the period from one of these addresses (an IPv6 /64).
 *   This is the worst case: when blocking, the safety valve and the
 *   addresses of administrators would have spared some of them.
 *
 * Each administrator sees it until they close it, for at most SHOW_DAYS
 * after the period ended; a new learning period replaces it. Nothing is
 * recorded for it but when the period ended ({@see LearningService::lastPeriod()})
 * and which recap an administrator closed. The figures are kept in the
 * memory cache for CACHE_TTL seconds.
 *
 * @psalm-import-type IntrusionDetectionLearningRecap from ResponseDefinitions
 */
class LearningRecap {
	/** The namespace of its memory cache in {@see Caches} */
	public const CACHE = 'learning_recap';
	public const CACHE_TTL = 600;
	/** The recap is shown this long after the period ended */
	public const SHOW_DAYS = 14;
	/** At most this many detections are read for the addresses that would have been blocked */
	public const SCAN_LIMIT = 5000;
	/** At most this many of the administrators' own people are counted */
	public const ACCOUNTS_LIMIT = 200;
	/** At most this many of them are named */
	public const ACCOUNTS_SHOWN = 20;
	/** Addresses per login history query */
	private const CHUNK = 500;
	/** Checks of these categories are no attacks */
	private const NOT_ATTACKS = [Category::Internal, Category::Administration];

	public function __construct(
		private readonly LearningService $learning,
		private readonly StatsMapper $stats,
		private readonly LoginHistory $logins,
		private readonly CheckNames $names,
		private readonly AppSettings $settings,
		private readonly AppState $state,
		private readonly IUserConfig $userConfig,
		private readonly IUserManager $userManager,
		private readonly ITimeFactory $timeFactory,
		private readonly Caches $caches,
	) {
	}

	/**
	 * The recap an administrator has not closed yet, or null when there is none to show.
	 *
	 * @return ?IntrusionDetectionLearningRecap
	 */
	public function forAdmin(string $uid, IL10N $l): ?array {
		$period = $this->shown();
		if ($period === null || $this->userConfig->getValueInt($uid, Application::APP_ID, UserKeys::LEARNING_RECAP_CLOSED, lazy: true) >= $period[1]) {
			return null;
		}
		$key = $period[1] . ':' . $l->getLanguageCode();
		$recap = $this->caches->shared(self::CACHE)?->get($key);
		if (!is_array($recap) || ($recap['endedAt'] ?? null) !== $period[1]) {
			$recap = $this->build($period[0], $period[1], $l);
			$this->caches->shared(self::CACHE)?->set($key, $recap, self::CACHE_TTL);
		}
		/** @var IntrusionDetectionLearningRecap $recap */
		return $recap;
	}

	/**
	 * Close the recap for one administrator.
	 */
	public function close(string $uid): void {
		$period = $this->learning->lastPeriod();
		if ($period !== null) {
			$this->userConfig->setValueInt($uid, Application::APP_ID, UserKeys::LEARNING_RECAP_CLOSED, $period[1], lazy: true);
		}
	}

	/**
	 * The period whose recap is shown, or null.
	 *
	 * @return ?array{0: int, 1: int}
	 */
	private function shown(): ?array {
		$period = $this->learning->lastPeriod();
		if ($period === null || $this->timeFactory->getTime() - $period[1] > self::SHOW_DAYS * 86400) {
			return null;
		}
		return $period;
	}

	/**
	 * @return IntrusionDetectionLearningRecap
	 */
	private function build(int $start, int $end, IL10N $l): array {
		$attacks = array_filter(
			$this->stats->hitsPerCheckBetween($start, $end),
			fn (int $hits, string $checkId): bool => $hits > 0 && !in_array($this->names->category($checkId), self::NOT_ATTACKS, true),
			ARRAY_FILTER_USE_BOTH,
		);
		uksort($attacks, static fn (string $a, string $b): int => [$attacks[$b], $a] <=> [$attacks[$a], $b]);
		$top = array_key_first($attacks);

		$heldBack = $this->stats->heldBackByLearning($start, $end, self::SCAN_LIMIT);
		$uids = $this->accountsFrom($heldBack['addresses'], $start, $end);
		$accounts = array_map(fn (string $uid): array => ['uid' => $uid, 'displayName' => $this->userManager->getDisplayName($uid) ?? $uid], $uids);
		usort($accounts, static fn (array $a, array $b): int => strnatcasecmp($a['displayName'], $b['displayName']) ?: strcmp($a['uid'], $b['uid']));

		$keptSince = $this->timeFactory->getTime() - $this->settings->retentionDays() * 86400;
		return [
			'startedAt' => $start,
			'endedAt' => $end,
			'days' => max(1, (int)round(($end - $start) / 86400)),
			'first' => $start === $this->state->getInt(AppState::INSTALLED_AT),
			'attempts' => array_sum($attacks),
			'addresses' => $this->stats->addressesBetween(array_map('strval', array_keys($attacks)), $start, $end),
			'topAttack' => $top === null ? null : [
				'checkId' => $top,
				'name' => $this->names->name($top, $l),
				'summary' => $this->names->summary($top, $l),
				'attempts' => $attacks[$top],
			],
			'wouldHaveBlocked' => count($heldBack['addresses']),
			'ownPeople' => count($uids),
			'accounts' => array_slice($accounts, 0, self::ACCOUNTS_SHOWN),
			'complete' => $heldBack['complete'] && $start >= $keptSince,
		];
	}

	/**
	 * The different accounts with an accepted login in [since, until) from
	 * one of the addresses, at most ACCOUNTS_LIMIT.
	 *
	 * @param list<string> $addresses
	 * @return list<string>
	 */
	private function accountsFrom(array $addresses, int $since, int $until): array {
		$keys = ['ip' => [], 'net_key' => []];
		foreach ($addresses as $address) {
			$source = SourceKey::tryFromIp($address);
			if ($source !== null) {
				[$column, $match] = KeyMatch::address($source);
				$keys[$column][$match->exact[0]] = true;
			}
		}
		$uids = [];
		foreach ($keys as $column => $values) {
			foreach (array_chunk(array_map('strval', array_keys($values)), self::CHUNK) as $chunk) {
				$left = self::ACCOUNTS_LIMIT - count($uids);
				if ($left <= 0) {
					break 2;
				}
				foreach ($this->logins->acceptedUidsBetween($column, new KeyMatch($chunk), $since, $until, $left) as $uid) {
					$uids[$uid] = true;
				}
			}
		}
		return array_slice(array_map('strval', array_keys($uids)), 0, self::ACCOUNTS_LIMIT);
	}
}
