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
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Db\AttemptMapper;
use OCA\IntrusionDetection\Db\AttemptStats;
use OCA\IntrusionDetection\Detection\AttemptRecord;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\SourceKey;
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
 *    held to `net_factor` times these numbers. Both are lowered for an
 *    address with an elevated or high risk score ({@see RiskScorer::limits()}).
 * 2. Distributed: the whole server has at least the distributed numbers of
 *    failures, addresses and names within 10 minutes. That records one
 *    detection per 30 minutes while it lasts. During it, and for an hour
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
	/** With a memory cache, each web server evaluates the instance-wide numbers at most this often */
	public const EVALUATE_EVERY = 30;
	/** A network detection blocks at most this many of its addresses */
	public const MAX_NET_TARGETS = 256;

	private ?IMemcache $cache = null;
	private bool $cacheInitialised = false;

	public function __construct(
		private readonly Settings $settings,
		private readonly AttemptMapper $attempts,
		private readonly ResponseEngine $engine,
		private readonly FlaggedSources $flags,
		private readonly BanService $bans,
		private readonly RemoteAddressResolver $addresses,
		private readonly ICacheFactory $cacheFactory,
		private readonly RiskScorer $risk,
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
				foreach ($this->attempts->distinctIpKeys('net_key', [$source->netKey], self::KINDS, $since, self::MAX_NET_TARGETS) as $ipKey) {
					$target = SourceKey::tryFromIpKey($ipKey);
					if ($target !== null) {
						$draft->addBanTarget($target);
					}
				}
				$this->engine->handle($draft);
			}
		}

		$this->distributed($attempt, $state, $params, $window === self::DISTRIBUTED_WINDOW ? $ip : null);
	}

	/**
	 * @param array<string, int|float|bool|string|list<string>> $params
	 */
	private function distributed(#[\SensitiveParameter] AttemptRecord $attempt, ModeState $state, array $params, ?AttemptStats $ipStats): void {
		$now = $attempt->time;
		$until = $this->settings->getInt(GlobalSettings::CS_DISTRIBUTED_UNTIL);

		if ($this->evaluationDue($now)) {
			$instance = $this->attempts->instanceStats(self::KINDS, $now - self::DISTRIBUTED_WINDOW);
			if ($instance->failures >= (int)$params['distributed_min_failures']
				&& $instance->distinctSources >= (int)$params['distributed_min_sources']
				&& $instance->distinctNames >= (int)$params['distributed_min_names']) {
				// Written at most once a minute, not on every failure.
				if ($until < $now + self::DISTRIBUTED_WINDOW - 60) {
					$until = $now + self::DISTRIBUTED_WINDOW;
					$this->settings->setGlobal(GlobalSettings::CS_DISTRIBUTED_UNTIL, $until);
				}
				if ($now - $this->settings->getInt(GlobalSettings::CS_DISTRIBUTED_DETECTED_AT) >= self::DISTRIBUTED_DEDUPE) {
					$this->recordDistributed($instance, $now);
				}
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
			$this->bans->ban($attempt->source, CredentialStuffing::ID, $detectionId);
		}
	}

	/**
	 * The instance-wide numbers are evaluated at most every EVALUATE_EVERY
	 * seconds: per web server with a memory cache, else instance-wide through
	 * a stored time. Without a cache, requests that run at the same moment
	 * may each evaluate once; there is never one evaluation per failure.
	 */
	private function evaluationDue(int $now): bool {
		$cache = $this->cache();
		if ($cache !== null) {
			return $cache->add('cs:eval', 1, self::EVALUATE_EVERY);
		}
		$last = $this->settings->getInt(GlobalSettings::CS_EVALUATED_AT);
		if ($last <= $now && $now - $last < self::EVALUATE_EVERY) {
			return false;
		}
		$this->settings->setGlobal(GlobalSettings::CS_EVALUATED_AT, $now);
		return true;
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

	private function cache(): ?IMemcache {
		if (!$this->cacheInitialised) {
			$this->cacheInitialised = true;
			$cache = $this->cacheFactory->isLocalCacheAvailable() ? $this->cacheFactory->createLocal(Application::APP_ID) : null;
			// add() is atomic only on the memcache types.
			$this->cache = $cache instanceof IMemcache ? $cache : null;
		}
		return $this->cache;
	}
}
