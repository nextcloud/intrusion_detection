<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Confirm\LoginContext;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Db\AttemptMapper;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Detection\AttemptRecord;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCA\IntrusionDetection\Risk\RiskScorer;
use OCP\ICache;
use OCP\ICacheFactory;

/**
 * Detects password spraying (concept section 10.2) after each failed
 * password login.
 *
 * - A failed attempt with a password that is already flagged blocks its
 *   address at once.
 * - Otherwise: attempts with the same password fingerprint within `window`
 *   (at most one hour) for at least `min_names` different login names fire.
 *   The limit is lowered when the failing address has an elevated or high
 *   risk score ({@see RiskScorer::limits()}).
 *   Every address that tried it in the window is blocked (at most
 *   MAX_BAN_TARGETS), and the fingerprint is flagged for a day.
 *
 * - A successful login with a flagged password ({@see self::detectSuccess()})
 *   is a detection of its own for the account, with the login responses
 *   (extra confirmation, telling the user, a new password). Whether the
 *   login needs confirmation is decided by the step-up reasons, which read
 *   the same flag.
 */
class PasswordSprayingDetector {
	public const KINDS = [AttemptKind::PasswordLogin];

	private ?ICache $cache = null;
	private bool $cacheInitialised = false;

	public function __construct(
		private readonly Settings $settings,
		private readonly AttemptMapper $attempts,
		private readonly ResponseEngine $engine,
		private readonly FlaggedSources $flags,
		private readonly Fingerprinter $fingerprinter,
		private readonly ICacheFactory $cacheFactory,
		private readonly PasswordSpraying $check,
		private readonly RiskScorer $risk,
	) {
	}

	/**
	 * A successful password login: when its password is flagged, record a
	 * detection for the account, merged per account and hour, and run the
	 * login responses.
	 *
	 * @return ?Detection the detection, or null when the password is not flagged or the check is off
	 */
	public function detectSuccess(LoginContext $login): ?Detection {
		if (!$login->passwordFlagged || !$this->settings->modeState(PasswordSpraying::ID)->runs()) {
			return null;
		}
		$draft = new DetectionDraft(
			checkId: PasswordSpraying::ID,
			source: $login->source,
			uid: $login->uid(),
			facts: ['rule' => PasswordSpraying::RULE_LOGIN, 'client' => !$login->interactive],
			merge: DetectionDraft::MERGE_USER,
			userAgent: $login->userAgent,
		);
		return $this->engine->handle($draft, $this->check->responsesFor($draft, $this->settings->responses(PasswordSpraying::ID), []));
	}

	public function detect(#[\SensitiveParameter] AttemptRecord $attempt, ?string $userAgent, #[\SensitiveParameter] ?string $password): void {
		if ($attempt->kind !== AttemptKind::PasswordLogin || $attempt->passwordCandidates === [] || $password === null || $password === '') {
			return;
		}
		$state = $this->settings->modeState(PasswordSpraying::ID);
		if (!$state->runs()) {
			return;
		}

		if ($this->flags->isPasswordFlagged($attempt->passwordCandidates)) {
			$this->banJoiningSource($attempt, $userAgent);
			return;
		}

		$window = min(3600, $this->settings->paramInt(PasswordSpraying::ID, 'window'));
		$since = $attempt->time - $window;
		$stats = $this->attempts->stats('pw_fp', $attempt->passwordCandidates, self::KINDS, $since);
		$limits = $this->risk->limits($attempt->source, ['min_names' => [$this->settings->paramInt(PasswordSpraying::ID, 'min_names'), $stats->distinctNames]]);
		if (!$limits->reached()) {
			return;
		}
		// Without a flag (Observe, or the response switched off) every further
		// attempt would fire again and re-block every address; one detection
		// per spray and window is enough, later addresses are blocked singly.
		// The cache key is derived from the fingerprint and never stored.
		$flags = $state->acts() && $this->settings->hasResponse(PasswordSpraying::ID, ResponseType::FlagPassword);
		$seenKey = 'spray:' . hash('sha256', $attempt->passwordCandidates[0]);
		if (!$flags && $this->cache()?->get($seenKey) !== null) {
			if ($state->acts()) {
				$this->banJoiningSource($attempt, $userAgent);
			}
			return;
		}

		$targets = $this->attempts->distinctIpKeys('pw_fp', $attempt->passwordCandidates, self::KINDS, $since, PasswordSpraying::MAX_BAN_TARGETS);
		$draft = new DetectionDraft(
			checkId: PasswordSpraying::ID,
			source: $attempt->source,
			facts: [
				'rule' => PasswordSpraying::RULE_SPRAY,
				'failures' => $stats->failures,
				'names' => $stats->distinctNames,
				'sources' => $stats->distinctSources,
				'banTargets' => count($targets),
				'first' => $stats->first,
				'last' => $stats->last,
				'targets' => $this->attempts->distinctUids('pw_fp', $attempt->passwordCandidates, self::KINDS, $since, 20),
			] + $limits->facts(),
			merge: DetectionDraft::MERGE_SOURCE,
			userAgent: $userAgent,
		);
		foreach ($targets as $ipKey) {
			$target = SourceKey::tryFromIpKey($ipKey);
			if ($target !== null) {
				$draft->addBanTarget($target);
			}
		}
		$draft->setPasswordFingerprints(array_merge(
			$attempt->passwordCandidates,
			array_map('bin2hex', $this->fingerprinter->passwordFlagFingerprints($password)),
		));
		$this->engine->handle($draft, $this->check->responsesFor($draft, $this->settings->responses(PasswordSpraying::ID), []));
		if (!$flags) {
			$this->cache()?->set($seenKey, 1, $window);
		}
	}

	/**
	 * An address that joins a spray already detected: blocked at once,
	 * without evaluating the whole spray again.
	 */
	private function banJoiningSource(#[\SensitiveParameter] AttemptRecord $attempt, ?string $userAgent): void {
		$this->engine->handle(new DetectionDraft(
			checkId: PasswordSpraying::ID,
			source: $attempt->source,
			facts: ['rule' => PasswordSpraying::RULE_FLAGGED],
			merge: DetectionDraft::MERGE_SOURCE,
			userAgent: $userAgent,
		), array_values(array_filter(
			$this->settings->responses(PasswordSpraying::ID),
			static fn (ResponseType $r): bool => $r === ResponseType::Ban,
		)));
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
