<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Config\Prerequisites;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Db\AttemptMapper;
use OCA\IntrusionDetection\Db\AttemptStats;
use OCA\IntrusionDetection\Db\StateMapper;
use OCA\IntrusionDetection\Detection\AttemptRecord;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\BanResult;
use OCA\IntrusionDetection\Response\BanService;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCA\IntrusionDetection\Risk\RiskScorer;
use OCP\ICacheFactory;
use OCP\IMemcache;

/**
 * Detects credential stuffing (concept section 10.1) after each failed login.
 *
 * 1. Single source: the address has at least `min_failures` failures for at
 *    least `min_names` different login names within `window`. An IPv4 /24 is
 *    held to `net_factor` times these numbers; then its addresses with at
 *    least 2 failures for 2 names are blocked, or the /24 itself when none
 *    has. Both are lowered for an address with an elevated or high risk
 *    score ({@see RiskScorer::limits()}).
 * 2. Distributed: the whole server has at least the distributed numbers of
 *    failures, addresses and names within 10 minutes. One web server
 *    evaluates this for all, once every EVALUATE_EVERY seconds
 *    ({@see evaluationDue()}). It records one detection per 30 minutes
 *    while it lasts. During it, and for an hour
 *    after, every failing address is flagged; during it, every address with
 *    3 failures for 2 names is blocked.
 */
class CredentialStuffingDetector {
	public const KINDS = [AttemptKind::PasswordLogin, AttemptKind::AppPassword];
	public const DISTRIBUTED_WINDOW = 600;
	/** At most one distributed detection per this many seconds while an attack lasts */
	public const DISTRIBUTED_DEDUPE = 1800;
	/** Failing addresses stay flagged this long after a distributed attack */
	public const DISTRIBUTED_FLAG_AFTER = 3600;
	public const MEMBER_MIN_FAILURES = 3;
	public const MEMBER_MIN_NAMES = 2;
	/** The instance-wide numbers are evaluated once per period of this many seconds, on one web server */
	public const EVALUATE_EVERY = 30;
	/** The ids_state row that holds the last period claimed for that evaluation, without a distributed cache */
	public const EVALUATED_STATE = 'cs_evaluated';
	/** A network detection blocks at most this many of its addresses */
	public const MAX_NET_TARGETS = 256;
	/** A network detection blocks those of its addresses that failed this often for this many names */
	public const NET_MEMBER_MIN_FAILURES = 2;
	public const NET_MEMBER_MIN_NAMES = 2;

	private ?IMemcache $sharedCache = null;
	private ?IMemcache $localCache = null;
	private bool $cachesInitialised = false;

	public function __construct(
		private readonly Settings $settings,
		private readonly AttemptMapper $attempts,
		private readonly ResponseEngine $engine,
		private readonly FlaggedSources $flags,
		private readonly BanService $bans,
		private readonly RemoteAddressResolver $addresses,
		private readonly ICacheFactory $cacheFactory,
		private readonly RiskScorer $risk,
		private readonly StateMapper $state,
		private readonly Prerequisites $prerequisites,
	) {
	}

	public function detect(#[\SensitiveParameter] AttemptRecord $attempt, ?string $userAgent): void {
		if (!in_array($attempt->kind, self::KINDS, true)) {
			return;
		}
		$state = $this->settings->modeState(CredentialStuffing::ID);
		if (!$state->runs()) {
			return;
		}
		$params = $this->settings->params(CredentialStuffing::ID);
		$window = (int)$params['window'];
		$minFailures = (int)$params['min_failures'];
		$minNames = (int)$params['min_names'];
		$factor = (int)$params['net_factor'];
		$source = $attempt->source;
		$now = $attempt->time;
		$since = $now - $window;

		$ip = $this->attempts->stats('ip_key', [$source->ipKey], self::KINDS, $since);
		$limits = $this->risk->limits($source, self::limits($ip, $minFailures, $minNames));
		if ($limits->reached()) {
			$this->engine->handle(new DetectionDraft(
				checkId: CredentialStuffing::ID,
				source: $source,
				facts: $this->facts(CredentialStuffing::RULE_SOURCE, $ip) + [
					'targets' => $this->attempts->distinctUids('ip_key', [$source->ipKey], self::KINDS, $since, 20),
				] + $limits->facts(),
				merge: DetectionDraft::MERGE_SOURCE,
				userAgent: $userAgent,
			));
		} elseif ($source->family === 4 && $factor > 0) {
			$net = $this->attempts->stats('net_key', [$source->netKey], self::KINDS, $since);
			$netLimits = $net->distinctSources > 1 ? $this->risk->limits($source, self::limits($net, $minFailures * $factor, $minNames * $factor)) : null;
			if ($netLimits !== null && $netLimits->reached()) {
				$draft = new DetectionDraft(
					checkId: CredentialStuffing::ID,
					source: $source,
					facts: $this->facts(CredentialStuffing::RULE_NETWORK, $net) + [
						'net' => $source->netKey,
						'targets' => $this->attempts->distinctUids('net_key', [$source->netKey], self::KINDS, $since, 20),
					] + $netLimits->facts(),
					merge: DetectionDraft::MERGE_SOURCE,
					userAgent: $userAgent,
				);
				$this->addNetworkTargets($draft, $since);
				$this->engine->handle($draft);
			}
		}

		$this->distributed($attempt, $state, $params, $window === self::DISTRIBUTED_WINDOW ? $ip : null);
	}

	/**
	 * The addresses of the network that each failed at least
	 * NET_MEMBER_MIN_FAILURES times for NET_MEMBER_MIN_NAMES names; a
	 * neighbour who mistyped once is no target. When none did, the attack
	 * is spread thinly over the network, and the /24 itself is the target.
	 */
	private function addNetworkTargets(DetectionDraft $draft, int $since): void {
		$source = $draft->source;
		if ($source === null) {
			return;
		}
		$targets = [];
		foreach ($this->attempts->countsPerSource('net_key', [$source->netKey], self::KINDS, $since, self::MAX_NET_TARGETS) as $ipKey => $counts) {
			$target = $counts['failures'] >= self::NET_MEMBER_MIN_FAILURES && $counts['names'] >= self::NET_MEMBER_MIN_NAMES ? SourceKey::tryFromIpKey((string)$ipKey) : null;
			if ($target !== null) {
				$targets[$target->ipKey] = $target;
			}
		}
		if (!isset($targets[$source->ipKey])) {
			$draft->spareSource();
		}
		foreach ($targets as $target) {
			$draft->addBanTarget($target);
		}
		if ($targets === []) {
			$draft->addNetworkBanTarget($source);
		}
	}

	/**
	 * @param array<string, int|float|bool|string|list<string>> $params
	 */
	private function distributed(#[\SensitiveParameter] AttemptRecord $attempt, ModeState $state, array $params, ?AttemptStats $ipStats): void {
		$now = $attempt->time;
		$until = $this->settings->getInt(GlobalSettings::CS_DISTRIBUTED_UNTIL);

		$since = $now - self::DISTRIBUTED_WINDOW;
		if ($this->evaluationDue($now) && $this->attempts->instanceReaches(
			self::KINDS,
			$since,
			(int)$params['distributed_min_failures'],
			(int)$params['distributed_min_sources'],
			(int)$params['distributed_min_names'],
		)) {
			// Written at most once a minute, not on every failure.
			if ($until < $now + self::DISTRIBUTED_WINDOW - 60) {
				$until = $now + self::DISTRIBUTED_WINDOW;
				$this->settings->setGlobal(GlobalSettings::CS_DISTRIBUTED_UNTIL, $until);
			}
			if ($now - $this->settings->getInt(GlobalSettings::CS_DISTRIBUTED_DETECTED_AT) >= self::DISTRIBUTED_DEDUPE) {
				$this->recordDistributed($this->attempts->instanceStats(self::KINDS, $since), $now);
			}
		}

		if ($now < $until + self::DISTRIBUTED_FLAG_AFTER) {
			$this->member($attempt, $state, $until, $ipStats);
		}
	}

	private function recordDistributed(AttemptStats $instance, int $now): void {
		// Only the notification applies to the attack as a whole: the blocks and
		// flags are for the single addresses taking part, below.
		$responses = array_values(array_filter(
			$this->settings->responses(CredentialStuffing::ID),
			static fn (ResponseType $r): bool => $r === ResponseType::NotifyAdmin,
		));
		$this->settings->setGlobal(GlobalSettings::CS_DISTRIBUTED_DETECTED_AT, $now);
		$detection = $this->engine->handle(new DetectionDraft(
			checkId: CredentialStuffing::ID,
			facts: $this->facts(CredentialStuffing::RULE_DISTRIBUTED, $instance) + ['distributed' => true],
		), $responses);
		$this->settings->setGlobal(GlobalSettings::CS_DISTRIBUTED_DETECTION, $detection?->getId() ?? 0);
	}

	/**
	 * An address failing during a distributed attack: flag it, and block it
	 * once it failed 3 times for 2 names.
	 */
	private function member(#[\SensitiveParameter] AttemptRecord $attempt, ModeState $state, int $until, ?AttemptStats $ipStats): void {
		if (!$state->acts() || $this->addresses->isNeverBlocked($attempt->source)) {
			return;
		}
		$now = $attempt->time;
		$detectionId = $this->settings->getInt(GlobalSettings::CS_DISTRIBUTED_DETECTION) ?: null;
		$responses = $this->settings->responses(CredentialStuffing::ID);
		if (in_array(ResponseType::FlagSource, $responses, true)) {
			$this->flags->flagSource($attempt->source, FlaggedSources::REASON_DISTRIBUTED, $detectionId, $until + self::DISTRIBUTED_FLAG_AFTER - $now);
		}
		if ($now >= $until || !in_array(ResponseType::Ban, $responses, true)) {
			return;
		}
		$stats = $ipStats ?? $this->attempts->stats('ip_key', [$attempt->source->ipKey], self::KINDS, $now - self::DISTRIBUTED_WINDOW);
		if (self::reaches($stats, self::MEMBER_MIN_FAILURES, self::MEMBER_MIN_NAMES)) {
			$result = $this->bans->ban($attempt->source, CredentialStuffing::ID, $detectionId);
			if (($result->outcome === BanResult::SKIPPED_SHARED || $result->outcome === BanResult::SKIPPED_PROXY) && $this->bans->firstReport($attempt->source)) {
				$this->engine->handle(SharedAddress::draft($attempt->source, $result->sharedUsers, CredentialStuffing::ID, $result->outcome === BanResult::SKIPPED_PROXY));
			}
		}
	}

	/**
	 * The instance-wide numbers are evaluated once per EVALUATE_EVERY-second
	 * period, by the first failure of the period on any web server, so the
	 * cost of the count does not grow with the number of web servers:
	 * - with a distributed cache, by the request whose add() of the
	 *   period's key succeeds;
	 * - otherwise by the request that claims the period in ids_state. A
	 *   local cache lets each web server try that claim once per period.
	 */
	private function evaluationDue(int $now): bool {
		$period = intdiv($now, self::EVALUATE_EVERY);
		$key = 'cs:eval:' . $period;
		$this->initCaches();
		if ($this->sharedCache !== null) {
			return $this->sharedCache->add($key, 1, self::EVALUATE_EVERY);
		}
		if ($this->localCache !== null && !$this->localCache->add($key, 1, self::EVALUATE_EVERY)) {
			return false;
		}
		return $this->state->claim(self::EVALUATED_STATE, $period);
	}

	/**
	 * @return array<string, mixed>
	 */
	private function facts(string $rule, AttemptStats $stats): array {
		return [
			'rule' => $rule,
			'failures' => $stats->failures,
			'names' => $stats->distinctNames,
			'sources' => $stats->distinctSources,
			'first' => $stats->first,
			'last' => $stats->last,
		];
	}

	private static function reaches(AttemptStats $stats, int $failures, int $names): bool {
		return $stats->failures >= $failures && $stats->distinctNames >= $names;
	}

	/**
	 * The limits of the single-source rules with what was measured, for the risk score.
	 *
	 * @return array<string, array{0: int, 1: int}>
	 */
	private static function limits(AttemptStats $stats, int $failures, int $names): array {
		return ['min_failures' => [$failures, $stats->failures], 'min_names' => [$names, $stats->distinctNames]];
	}

	private function initCaches(): void {
		if ($this->cachesInitialised) {
			return;
		}
		$this->cachesInitialised = true;
		// add() is atomic only on the memcache types.
		$shared = $this->prerequisites->hasDistributedCache() ? $this->cacheFactory->createDistributed(Application::APP_ID) : null;
		$this->sharedCache = $shared instanceof IMemcache ? $shared : null;
		if ($this->sharedCache === null && $this->cacheFactory->isLocalCacheAvailable()) {
			$local = $this->cacheFactory->createLocal(Application::APP_ID);
			$this->localCache = $local instanceof IMemcache ? $local : null;
		}
	}
}
