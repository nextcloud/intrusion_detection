<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Risk;

use OCA\IntrusionDetection\Address\AddressCache;
use OCA\IntrusionDetection\Address\Verdict;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Blocklist\BlocklistSource;
use OCA\IntrusionDetection\Check\Checks\BlocklistMatch;
use OCA\IntrusionDetection\Check\Checks\ReservedName;
use OCA\IntrusionDetection\Check\Checks\TrapUrl;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Db\AttemptMapper;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Guard\RequestContext;
use OCA\IntrusionDetection\Lockdown\LockdownState;
use OCA\IntrusionDetection\Net\RangeCodec;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\ICache;
use OCP\ICacheFactory;
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
 * It is computed only where a decision is made, never per request: by the
 * login-failure checks when a count is close to its limit
 * ({@see self::limits()}), at successful password logins (the `risk_high`
 * step-up reason), and when a new detection is stored, for its explanation.
 * A failure is logged and gives the neutral score: the score must never
 * break the path it is asked on.
 */
class RiskScorer {
	public const FAILURES_PER_STEP = 5;
	public const MAX_FAILURE_STEPS = 3;
	public const FAILURES_WINDOW = 3600;
	public const TRAP_WINDOW = 86400;
	public const CACHE_TTL = 60;
	/** The checks whose detections count as a trap hit */
	public const TRAP_CHECKS = [TrapUrl::ID, ReservedName::ID];
	private const FAILURE_KINDS = [AttemptKind::PasswordLogin, AttemptKind::AppPassword];
	private const CACHE_PREFIX = 'risk:';

	private ?ICache $cache = null;
	private bool $cacheInitialised = false;

	public function __construct(
		private readonly Settings $settings,
		private readonly FlaggedSources $flags,
		private readonly AttemptMapper $attempts,
		private readonly DetectionMapper $detections,
		private readonly RequestContext $context,
		private readonly AddressCache $addressCache,
		private readonly RemoteAddressResolver $addresses,
		private readonly AttackTools $tools,
		private readonly ICacheFactory $cacheFactory,
		private readonly ITimeFactory $timeFactory,
		private readonly LoggerInterface $logger,
		private readonly LockdownState $lockdown,
	) {
	}

	public function isEnabled(): bool {
		return $this->settings->getBool(GlobalSettings::RISK_ENABLED);
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
	 * The count limits of one rule for an address, lowered by its risk score
	 * and by lockdown mode: the limit times the risk tier's factor times the
	 * lockdown factor, rounded up, but never below 2 (one multiplication, so
	 * the two never compound below the floor). `$caps` set a limit to at
	 * most a value on top, as lockdown does for share passwords.
	 *
	 * The score is only computed when it can change the outcome: when every
	 * measured value reaches the lowest limit the score could give, but not
	 * all reach the configured limits. Below that, and at or above the
	 * configured limits, no query is made.
	 *
	 * @param array<string, array{0: int, 1: int}> $limits per parameter name: the configured limit and the measured value
	 * @param array<string, int> $caps per parameter name: the highest the limit may be
	 */
	public function limits(?SourceKey $source, array $limits, array $caps = []): RiskLimits {
		$plain = array_map(static fn (array $l): int => $l[0], $limits);
		$measured = array_map(static fn (array $l): int => $l[1], $limits);
		$lockdown = $this->lockdown->limitFactor();
		if ($this->allReach($measured, $plain)) {
			return new RiskLimits($plain, $plain, $measured, null);
		}
		$scored = $source !== null && $this->isEnabled();
		$lowest = $scored
			? min(1.0, $this->settings->global(GlobalSettings::RISK_FACTOR_ELEVATED), $this->settings->global(GlobalSettings::RISK_FACTOR_HIGH))
			: 1.0;
		if (!$this->allReach($measured, self::lowered($plain, (float)$lowest * $lockdown, $caps))) {
			return new RiskLimits($plain, $plain, $measured, null);
		}
		$risk = $scored ? $this->score($source) : null;
		return new RiskLimits($plain, self::lowered($plain, ($risk?->factor ?? 1.0) * $lockdown, $caps), $measured, $risk, $lockdown, $caps);
	}

	/**
	 * @param array<string, int> $limits
	 * @param array<string, int> $caps
	 * @return array<string, int>
	 */
	private static function lowered(array $limits, float $factor, array $caps): array {
		$lowered = [];
		foreach ($limits as $name => $limit) {
			$lowered[$name] = min(RiskAssessment::lowerBy($limit, $factor), $caps[$name] ?? PHP_INT_MAX);
		}
		return $lowered;
	}

	/**
	 * A failed password login: remember an attack tool's user agent on the
	 * address for a day. One regular expression; a write only for a tool.
	 */
	public function noteFailedLogin(SourceKey $source, ?string $userAgent): void {
		if (!$this->isEnabled()) {
			return;
		}
		$tool = $this->tools->match($userAgent, $this->list(GlobalSettings::RISK_ATTACK_TOOL_PATTERNS));
		if ($tool === null) {
			return;
		}
		$this->flags->flagAttackTool($source, $tool);
		// The cached facts would miss the tool for up to a minute.
		$this->cache()?->remove(self::CACHE_PREFIX . $source->ipKey);
	}

	private function assess(SourceKey $source): RiskAssessment {
		$points = fn (string $setting): int => $this->settings->getInt($setting);
		$parts = [];
		$add = static function (string $fact, int $value, ?string $detail = null) use (&$parts): void {
			if ($value !== 0) {
				$parts[] = ['fact' => $fact, 'points' => $value, 'detail' => $detail];
			}
		};

		$facts = $this->storedFacts($source);
		if ($facts['tool'] !== null) {
			$add(RiskAssessment::FACT_ATTACK_TOOL, $points(GlobalSettings::RISK_POINTS_ATTACK_TOOL), $facts['tool']);
		}

		$verdict = $this->verdict($source);
		if ($verdict !== null) {
			if ($verdict->hasAttribute(BlocklistSource::PURPOSE_TOR)) {
				$add(RiskAssessment::FACT_TOR, $points(GlobalSettings::RISK_POINTS_TOR));
			}
			if ($verdict->hasAttribute(BlocklistSource::PURPOSE_HOSTING)) {
				$add(RiskAssessment::FACT_HOSTING, $points(GlobalSettings::RISK_POINTS_HOSTING));
			}
			$lists = BlocklistMatch::listsOf($verdict);
			if ($lists !== []) {
				$add(RiskAssessment::FACT_BLOCKLIST, $points(GlobalSettings::RISK_POINTS_BLOCKLIST), implode(', ', $lists));
			}
		}

		if ($facts['traps'] !== []) {
			$add(RiskAssessment::FACT_TRAP, $points(GlobalSettings::RISK_POINTS_TRAP), implode(', ', $facts['traps']));
		}
		if ($facts['flag'] !== null) {
			$add(RiskAssessment::FACT_FLAGGED, $points(GlobalSettings::RISK_POINTS_FLAGGED), $facts['flag']);
		}
		$steps = min(self::MAX_FAILURE_STEPS, intdiv($facts['failures'], self::FAILURES_PER_STEP));
		if ($steps > 0) {
			$add(RiskAssessment::FACT_FAILURES, $steps * $points(GlobalSettings::RISK_POINTS_FAILURES), (string)$facts['failures']);
		}

		$office = RangeCodec::firstContaining($this->list(GlobalSettings::RISKY_NETWORK_OFFICE_NETWORKS), $source);
		if ($office !== null) {
			$add(RiskAssessment::FACT_OFFICE, $points(GlobalSettings::RISK_POINTS_OFFICE), $office);
		}

		return RiskAssessment::of(
			$parts,
			$points(GlobalSettings::RISK_TIER_ELEVATED),
			$points(GlobalSettings::RISK_TIER_HIGH),
			(float)$this->settings->global(GlobalSettings::RISK_FACTOR_ELEVATED),
			(float)$this->settings->global(GlobalSettings::RISK_FACTOR_HIGH),
		);
	}

	/**
	 * The verdict of the current request's address from the address check,
	 * or a cached one. Never resolved here: that would be a lookup of its own.
	 */
	private function verdict(SourceKey $source): ?Verdict {
		$current = $this->context->verdict();
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
		$cached = $this->cache()?->get($key);
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
		$this->cache()?->set($key, $facts, self::CACHE_TTL);
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

	/**
	 * @return list<string>
	 */
	private function list(string $setting): array {
		$value = $this->settings->global($setting);
		return is_array($value) ? $value : [];
	}

	private function cache(): ?ICache {
		if (!$this->cacheInitialised) {
			$this->cacheInitialised = true;
			if ($this->cacheFactory->isAvailable()) {
				$this->cache = $this->cacheFactory->createDistributed(Application::APP_ID);
			} elseif ($this->cacheFactory->isLocalCacheAvailable()) {
				$this->cache = $this->cacheFactory->createLocal(Application::APP_ID);
			}
		}
		return $this->cache;
	}
}
