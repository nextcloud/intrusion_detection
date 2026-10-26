<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Risk;

use OCA\IntrusionDetection\Address\AddressCache;
use OCA\IntrusionDetection\Address\Verdict;
use OCA\IntrusionDetection\Blocklist\BlocklistSource;
use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Check\Checks\BlocklistMatch\BlocklistMatch;
use OCA\IntrusionDetection\Check\Checks\ReservedName\ReservedName;
use OCA\IntrusionDetection\Check\Checks\TrapUrl\TrapUrl;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Db\AttemptMapper;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Login\RequestContext;
use OCA\IntrusionDetection\Net\AttackTools;
use OCA\IntrusionDetection\Net\RangeCodec;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCP\AppFramework\Utility\ITimeFactory;
use Psr\Log\LoggerInterface;

/**
 * The address risk score (concept section 10.18): points for one address
 * from facts that are already at hand.
 *
 * - From the address verdict the address check already has (no lookup):
 *   Tor, hosting, an observed blocklist.
 * - From the database, cached per address for CACHE_TTL seconds in the
 *   memory cache: an attack tool on a failed login and a flag (one query on
 *   the flags), a trap URL or reserved-name hit in the last 24 hours (one on
 *   the detections), and failed logins in the last hour (one on the attempts).
 * - From the settings: an office network takes points off.
 *
 * The points per fact are POINTS; the tiers and their factors are in
 * {@see RiskAssessment}.
 *
 * It is computed only where a decision is made, never per request: by the
 * login-failure checks when a count is close to its limit
 * ({@see self::limits()}), at successful password logins (the `risk_high`
 * step-up reason), and when a new detection is stored, for its explanation.
 * A failure is logged and gives the neutral score: the score must never
 * break the path it is asked on.
 */
class RiskScorer {
	/** The namespace of its memory cache in {@see Caches} */
	public const CACHE = 'risk';
	public const FAILURES_PER_STEP = 5;
	public const MAX_FAILURE_STEPS = 3;
	public const FAILURES_WINDOW = 3600;
	public const TRAP_WINDOW = 86400;
	public const CACHE_TTL = 60;
	/** Points per fact; for failed logins per FAILURES_PER_STEP of them */
	public const POINTS = [
		RiskAssessment::FACT_ATTACK_TOOL => 2,
		RiskAssessment::FACT_TOR => 2,
		RiskAssessment::FACT_HOSTING => 1,
		RiskAssessment::FACT_BLOCKLIST => 2,
		RiskAssessment::FACT_TRAP => 3,
		RiskAssessment::FACT_FLAGGED => 2,
		RiskAssessment::FACT_FAILURES => 1,
		RiskAssessment::FACT_OFFICE => -10,
	];
	/** The checks whose detections count as a trap hit */
	public const TRAP_CHECKS = [TrapUrl::ID, ReservedName::ID];
	private const FAILURE_KINDS = [AttemptKind::PasswordLogin, AttemptKind::AppPassword];
	private const CACHE_PREFIX = 'risk:';

	public function __construct(
		private readonly AppSettings $settings,
		private readonly FlaggedSources $flags,
		private readonly AttemptMapper $attempts,
		private readonly DetectionMapper $detections,
		private readonly RequestContext $context,
		private readonly AddressCache $addressCache,
		private readonly RemoteAddressResolver $addresses,
		private readonly AttackTools $tools,
		private readonly Caches $caches,
		private readonly ITimeFactory $timeFactory,
		private readonly LoggerInterface $logger,
	) {
	}

	public function isEnabled(): bool {
		return $this->settings->riskEnabled();
	}

	public function score(SourceKey $source): RiskAssessment {
		if (!$this->isEnabled()) {
			return RiskAssessment::neutral();
		}
		try {
			return $this->assess($source);
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not compute the risk score of an address', ['exception' => $e]);
			return RiskAssessment::neutral();
		}
	}

	/**
	 * The count limits of one rule for an address, lowered by its risk score.
	 *
	 * The score is only computed when it can change the outcome: when every
	 * measured value reaches the lowest limit the score could give, but not
	 * all reach the configured limits. Below that, and at or above the
	 * configured limits, no query is made.
	 *
	 * @param array<string, array{0: int, 1: int}> $limits per parameter name: the configured limit and the measured value
	 */
	public function limits(?SourceKey $source, array $limits): RiskLimits {
		$plain = array_map(static fn (array $l): int => $l[0], $limits);
		$measured = array_map(static fn (array $l): int => $l[1], $limits);
		if ($source === null || !$this->isEnabled() || $this->allReach($measured, $plain)) {
			return new RiskLimits($plain, $plain, $measured, null);
		}
		$possible = array_map($this->lowestLimit(...), $plain);
		if (!$this->allReach($measured, $possible)) {
			return new RiskLimits($plain, $plain, $measured, null);
		}
		$risk = $this->score($source);
		return new RiskLimits($plain, array_map(static fn (int $limit): int => $risk->lower($limit), $plain), $measured, $risk);
	}

	/**
	 * The lowest a count limit can become for an address with the highest
	 * risk score: the limit itself while the score is off.
	 */
	public function lowestLimit(int $limit): int {
		return $this->isEnabled() ? RiskAssessment::lowerBy($limit, min(RiskAssessment::FACTOR_ELEVATED, RiskAssessment::FACTOR_HIGH)) : $limit;
	}

	/**
	 * A failed password login: remember an attack tool's user agent on the
	 * address for a day. One regular expression; a write only for a tool.
	 */
	public function noteFailedLogin(SourceKey $source, ?string $userAgent): void {
		if (!$this->isEnabled()) {
			return;
		}
		$tool = $this->tools->match($userAgent);
		if ($tool === null) {
			return;
		}
		$key = self::CACHE_PREFIX . $source->ipKey;
		if ($this->flags->flagAttackTool($source, $tool)) {
			// The cached facts would miss a new tool for up to a minute.
			$this->caches->shared(self::CACHE)?->remove($key);
			return;
		}
		// The tool is known: the cached facts only miss this failure.
		$cached = $this->caches->shared(self::CACHE)?->get($key);
		if (is_array($cached) && is_int($cached['failures'] ?? null)) {
			$cached['failures']++;
			$this->caches->shared(self::CACHE)?->set($key, $cached, self::CACHE_TTL);
		}
	}

	private function assess(SourceKey $source): RiskAssessment {
		$parts = [];
		$add = static function (string $fact, ?string $detail = null, int $times = 1) use (&$parts): void {
			$parts[] = ['fact' => $fact, 'points' => $times * self::POINTS[$fact], 'detail' => $detail];
		};

		$facts = $this->storedFacts($source);
		if ($facts['tool'] !== null) {
			$add(RiskAssessment::FACT_ATTACK_TOOL, $facts['tool']);
		}

		$verdict = $this->verdict($source);
		if ($verdict !== null) {
			if ($verdict->hasAttribute(BlocklistSource::PURPOSE_TOR)) {
				$add(RiskAssessment::FACT_TOR);
			}
			if ($verdict->hasAttribute(BlocklistSource::PURPOSE_HOSTING)) {
				$add(RiskAssessment::FACT_HOSTING);
			}
			$lists = BlocklistMatch::listsOf($verdict);
			if ($lists !== []) {
				$add(RiskAssessment::FACT_BLOCKLIST, implode(', ', $lists));
			}
		}

		if ($facts['traps'] !== []) {
			$add(RiskAssessment::FACT_TRAP, implode(', ', $facts['traps']));
		}
		if ($facts['flag'] !== null) {
			$add(RiskAssessment::FACT_FLAGGED, $facts['flag']);
		}
		$steps = min(self::MAX_FAILURE_STEPS, intdiv($facts['failures'], self::FAILURES_PER_STEP));
		if ($steps > 0) {
			$add(RiskAssessment::FACT_FAILURES, (string)$facts['failures'], $steps);
		}

		$office = RangeCodec::firstContaining($this->settings->riskyNetworkOfficeNetworks(), $source);
		if ($office !== null) {
			$add(RiskAssessment::FACT_OFFICE, $office);
		}

		return RiskAssessment::of($parts);
	}

	/**
	 * The verdict of the current request's address from the address check,
	 * or a cached one. Never resolved here: that would be a lookup of its own.
	 */
	private function verdict(SourceKey $source): ?Verdict {
		$current = Verdict::of($this->context);
		if ($current !== null && $this->addresses->current()?->ip === $source->ip) {
			return $current;
		}
		return $this->addressCache->get($source);
	}

	/**
	 * @return array{tool: ?string, flag: ?string, traps: list<string>, failures: int}
	 */
	private function storedFacts(SourceKey $source): array {
		$key = self::CACHE_PREFIX . $source->ipKey;
		$cached = $this->caches->shared(self::CACHE)?->get($key);
		if (is_array($cached) && array_key_exists('tool', $cached) && array_key_exists('flag', $cached)
			&& is_array($cached['traps'] ?? null) && is_int($cached['failures'] ?? null)) {
			return [
				'tool' => is_string($cached['tool']) ? $cached['tool'] : null,
				'flag' => is_string($cached['flag']) ? $cached['flag'] : null,
				'traps' => array_values(array_filter($cached['traps'], 'is_string')),
				'failures' => $cached['failures'],
			];
		}
		$now = $this->timeFactory->getTime();
		$flags = $this->flags->riskFlags($source);
		$facts = [
			'tool' => $flags['tool'],
			'flag' => $flags['source'],
			'traps' => $this->detections->checksSeenFrom($source, self::TRAP_CHECKS, $now - self::TRAP_WINDOW),
			'failures' => $this->attempts->stats('ip_key', [$source->ipKey], self::FAILURE_KINDS, $now - self::FAILURES_WINDOW)->failures,
		];
		$this->caches->shared(self::CACHE)?->set($key, $facts, self::CACHE_TTL);
		return $facts;
	}

	/**
	 * @param array<string, int> $measured
	 * @param array<string, int> $limits
	 */
	private function allReach(array $measured, array $limits): bool {
		foreach ($limits as $name => $limit) {
			if (($measured[$name] ?? 0) < $limit) {
				return false;
			}
		}
		return true;
	}
}
