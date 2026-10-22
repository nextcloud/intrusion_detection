<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks;

use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Confirm\LoginContext;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Db\AttemptMapper;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Detection\AttemptRecord;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCA\IntrusionDetection\Risk\RiskScorer;

/**
 * Detects password spraying (concept section 10.2) after each failed
 * password login.
 *
 * - A failed attempt with a password that is already flagged blocks its
 *   address once it tried that password for MIN_NAMES_TO_BLOCK accounts.
 * - Otherwise: attempts with the same password fingerprint within `window`
 *   (at most one hour) for at least `min_names` different login names fire.
 *   The limit is lowered when the failing address has an elevated or high
 *   risk score ({@see RiskScorer::limits()}).
 *   The failing address is blocked, and so is every address that tried the
 *   password for at least MIN_NAMES_TO_BLOCK accounts in the window (at most
 *   MAX_BAN_TARGETS); the fingerprint is flagged for a day.
 *
 * - A successful login with a flagged password ({@see self::detectSuccess()})
 *   is a detection of its own for the account, with the login responses
 *   (extra confirmation, telling the user, a new password). Whether the
 *   login needs confirmation is decided by the step-up reasons, which read
 *   the same flag.
 */
class PasswordSprayingDetector {
	/** The namespace of its memory cache in {@see Caches} */
	public const CACHE = 'password-spraying';
	public const KINDS = [AttemptKind::PasswordLogin];

	public function __construct(
		private readonly CheckSettings $settings,
		private readonly AttemptMapper $attempts,
		private readonly ResponseEngine $engine,
		private readonly FlaggedSources $flags,
		private readonly Fingerprinter $fingerprinter,
		private readonly Caches $caches,
		private readonly PasswordSpraying $check,
		private readonly RiskScorer $risk,
	) {
	}

	/**
	 * A successful password login: when its password is flagged, record a
	 * detection for the account, merged per account, address and hour, and run the
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
			merge: DetectionDraft::MERGE_SOURCE_USER,
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

		// At most an hour, as long as attempts are kept (the parameter's maximum).
		$window = $this->settings->paramInt(PasswordSpraying::ID, 'window');
		// Without a flag (Observe, or the response switched off) every further
		// attempt would fire again and re-block every address; one detection
		// per spray and window is enough, later addresses are blocked singly,
		// without counting the spray again. The cache key is derived from the
		// fingerprint and never stored.
		$flags = $state->acts() && $this->settings->hasResponse(PasswordSpraying::ID, ResponseType::FlagPassword);
		$seenKey = 'spray:' . hash('sha256', $attempt->passwordCandidates[0]);
		if (!$flags && $this->caches->shared(self::CACHE)?->get($seenKey) !== null) {
			if ($state->acts()) {
				$this->banJoiningSource($attempt, $userAgent);
			}
			return;
		}

		$since = $attempt->time - $window;
		$stats = $this->attempts->stats('pw_fp', $attempt->passwordCandidates, self::KINDS, $since);
		$limits = $this->risk->limits($attempt->source, ['min_names' => [$this->settings->paramInt(PasswordSpraying::ID, 'min_names'), $stats->distinctNames]]);
		if (!$limits->reached()) {
			return;
		}

		$perSource = $this->attempts->countsPerSource('pw_fp', $attempt->passwordCandidates, self::KINDS, $since, PasswordSpraying::MAX_BAN_TARGETS);
		// Other addresses are blocked only when they tried the password for
		// several accounts themselves: one account is a person who mistyped.
		$targets = array_keys(array_filter($perSource, static fn (array $counts): bool => $counts['names'] >= PasswordSpraying::MIN_NAMES_TO_BLOCK));
		$draft = new DetectionDraft(
			checkId: PasswordSpraying::ID,
			source: $attempt->source,
			facts: [
				'rule' => PasswordSpraying::RULE_SPRAY,
				'failures' => $stats->failures,
				'names' => $stats->distinctNames,
				'sources' => $stats->distinctSources,
				'banTargets' => count($targets),
				'listed' => count($perSource),
				'first' => $stats->first,
				'last' => $stats->last,
				'targets' => $this->attempts->distinctUids('pw_fp', $attempt->passwordCandidates, self::KINDS, $since, 20),
			] + $limits->facts(),
			merge: DetectionDraft::MERGE_SOURCE,
			userAgent: $userAgent,
		);
		foreach ($targets as $ipKey) {
			$target = SourceKey::tryFromIpKey((string)$ipKey);
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
			$this->caches->shared(self::CACHE)?->set($seenKey, 1, $window);
		}
	}

	/**
	 * An address that joins a spray already detected: blocked once it tried
	 * the password for MIN_NAMES_TO_BLOCK accounts itself, like the other
	 * addresses of the spray, without evaluating the whole spray again.
	 * Someone who mistyped their own password, which happens to be the
	 * sprayed one, is no target.
	 */
	private function banJoiningSource(#[\SensitiveParameter] AttemptRecord $attempt, ?string $userAgent): void {
		$window = $this->settings->paramInt(PasswordSpraying::ID, 'window');
		$own = $this->attempts->statsForSourceWithPasswords($attempt->source->ipKey, $attempt->passwordCandidates, self::KINDS, $attempt->time - $window);
		if ($own->distinctNames < PasswordSpraying::MIN_NAMES_TO_BLOCK) {
			return;
		}
		$this->engine->handle(new DetectionDraft(
			checkId: PasswordSpraying::ID,
			source: $attempt->source,
			facts: ['rule' => PasswordSpraying::RULE_FLAGGED, 'names' => $own->distinctNames],
			merge: DetectionDraft::MERGE_SOURCE,
			userAgent: $userAgent,
		), array_values(array_filter(
			$this->settings->responses(PasswordSpraying::ID),
			static fn (ResponseType $r): bool => $r === ResponseType::Ban,
		)));
	}
}
