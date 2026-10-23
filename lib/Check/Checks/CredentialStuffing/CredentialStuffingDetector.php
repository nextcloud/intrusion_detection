<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\CredentialStuffing;

use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Check\Checks\SharedAddress\SharedAddress;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Db\AttemptMapper;
use OCA\IntrusionDetection\Db\AttemptStats;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Detection\AttemptRecord;
use OCA\IntrusionDetection\Detection\CommonFacts;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\BanResult;
use OCA\IntrusionDetection\Response\BanService;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\Risk\RiskScorer;
use OCA\IntrusionDetection\Signal\FailedLoginAttempt;
use OCA\IntrusionDetection\Signal\IDetector;
use OCA\IntrusionDetection\Signal\ISignal;
use OCA\IntrusionDetection\State\AppState;

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
 *    3 failures for 2 names is blocked. These blocks and flags belong to the
 *    detection of the attack, so they are made here, while the check acts.
 *
 * @template-implements IDetector<FailedLoginAttempt>
 */
class CredentialStuffingDetector implements IDetector {
	/** The namespace of its memory cache in {@see Caches} */
	public const CACHE = 'credential-stuffing';
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
	/** The last period claimed for that evaluation, without a distributed cache */
	public const EVALUATED_STATE = 'cs_evaluated';
	/** Until when a distributed attack counts as running */
	public const DISTRIBUTED_UNTIL_STATE = 'cs_distributed_until';
	/** When the running distributed attack was last recorded as a detection */
	public const DISTRIBUTED_DETECTED_AT_STATE = 'cs_distributed_detected_at';
	/** The detection of the running distributed attack */
	public const DISTRIBUTED_DETECTION_STATE = 'cs_distributed_detection';
	/** A network detection blocks at most this many of its addresses */
	public const MAX_NET_TARGETS = 256;
	/** A network detection blocks those of its addresses that failed this often for this many names */
	public const NET_MEMBER_MIN_FAILURES = 2;
	public const NET_MEMBER_MIN_NAMES = 2;

	public function __construct(
		private readonly CheckSettings $settings,
		private readonly AttemptMapper $attempts,
		private readonly FlaggedSources $flags,
		private readonly BanService $bans,
		private readonly RemoteAddressResolver $addresses,
		private readonly Caches $caches,
		private readonly RiskScorer $risk,
		private readonly AppState $state,
	) {
	}

	/**
	 * @param FailedLoginAttempt $signal
	 * @return \Generator<int, DetectionDraft, ?Detection, void>
	 */
	#[\Override]
	public function detect(#[\SensitiveParameter] ISignal $signal, ModeState $mode): \Generator {
		$attempt = $signal->attempt;
		$userAgent = $signal->userAgent;
		if (!in_array($attempt->kind, self::KINDS, true)) {
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
			yield new DetectionDraft(
				checkId: CredentialStuffing::ID,
				source: $source,
				facts: self::facts(
					CredentialStuffingRule::Source,
					$ip,
					targets: $this->attempts->distinctUids('ip_key', [$source->ipKey], self::KINDS, $since, 20),
					risk: $limits->facts(),
				),
				merge: DetectionDraft::MERGE_SOURCE,
				userAgent: $userAgent,
			);
		} elseif ($source->family === 4 && $factor > 0) {
			$net = $this->attempts->stats('net_key', [$source->netKey], self::KINDS, $since);
			$netLimits = $net->distinctSources > 1 ? $this->risk->limits($source, self::limits($net, $minFailures * $factor, $minNames * $factor)) : null;
			if ($netLimits !== null && $netLimits->reached()) {
				$draft = new DetectionDraft(
					checkId: CredentialStuffing::ID,
					source: $source,
					facts: self::facts(
						CredentialStuffingRule::Network,
						$net,
						net: $source->netKey,
						targets: $this->attempts->distinctUids('net_key', [$source->netKey], self::KINDS, $since, 20),
						risk: $netLimits->facts(),
					),
					merge: DetectionDraft::MERGE_SOURCE,
					userAgent: $userAgent,
				);
				$this->addNetworkTargets($draft, $since);
				yield $draft;
			}
		}

		yield from $this->distributed($attempt, $mode, $params, $window === self::DISTRIBUTED_WINDOW ? $ip : null);
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
	 * @return \Generator<int, DetectionDraft, ?Detection, void>
	 */
	private function distributed(#[\SensitiveParameter] AttemptRecord $attempt, ModeState $state, array $params, ?AttemptStats $ipStats): \Generator {
		$now = $attempt->time;
		$until = $this->state->getInt(self::DISTRIBUTED_UNTIL_STATE);

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
				$this->state->setInt(self::DISTRIBUTED_UNTIL_STATE, $until);
			}
			if ($now - $this->state->getInt(self::DISTRIBUTED_DETECTED_AT_STATE) >= self::DISTRIBUTED_DEDUPE) {
				yield from $this->recordDistributed($this->attempts->instanceStats(self::KINDS, $since), $now);
			}
		}

		if ($now < $until + self::DISTRIBUTED_FLAG_AFTER) {
			yield from $this->member($attempt, $state, $until, $ipStats);
		}
	}

	/**
	 * @return \Generator<int, DetectionDraft, ?Detection, void>
	 */
	private function recordDistributed(AttemptStats $instance, int $now): \Generator {
		$this->state->setInt(self::DISTRIBUTED_DETECTED_AT_STATE, $now);
		$detection = yield new DetectionDraft(
			checkId: CredentialStuffing::ID,
			facts: self::facts(CredentialStuffingRule::Distributed, $instance, distributed: true),
		);
		$this->state->set(self::DISTRIBUTED_DETECTION_STATE, $detection === null ? '' : (string)$detection->getId());
	}

	/**
	 * An address failing during a distributed attack: flag it, and block it
	 * once it failed 3 times for 2 names. An address many people log in from
	 * is reported instead.
	 *
	 * @return \Generator<int, DetectionDraft, ?Detection, void>
	 */
	private function member(#[\SensitiveParameter] AttemptRecord $attempt, ModeState $state, int $until, ?AttemptStats $ipStats): \Generator {
		if (!$state->acts() || $this->addresses->isNeverBlocked($attempt->source)) {
			return;
		}
		$now = $attempt->time;
		$detectionId = $this->state->get(self::DISTRIBUTED_DETECTION_STATE) ?: null;
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
				yield SharedAddress::draft($attempt->source, $result->sharedUsers, CredentialStuffing::ID, $result->outcome === BanResult::SKIPPED_PROXY);
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
		$shared = $this->caches->isDistributed() ? $this->caches->shared(self::CACHE) : null;
		if ($shared !== null) {
			return $shared->add($key, 1, self::EVALUATE_EVERY);
		}
		$local = $this->caches->local(self::CACHE);
		if ($local !== null && !$local->add($key, 1, self::EVALUATE_EVERY)) {
			return false;
		}
		return $this->state->claim(self::EVALUATED_STATE, $period);
	}

	/**
	 * @param ?list<string> $targets
	 * @param array<string, mixed> $risk
	 */
	private static function facts(CredentialStuffingRule $rule, AttemptStats $stats, ?string $net = null, ?array $targets = null, array $risk = [], ?bool $distributed = null): CredentialStuffingFacts {
		return new CredentialStuffingFacts(
			rule: $rule,
			failures: $stats->failures,
			names: $stats->distinctNames,
			sources: $stats->distinctSources,
			net: $net,
			distributed: $distributed,
			common: new CommonFacts(first: $stats->first, last: $stats->last, targets: $targets, risk: $risk),
		);
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

}
