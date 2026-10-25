<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\PasswordSpraying;

use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Db\AttemptMapper;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Detection\AttemptCounters;
use OCA\IntrusionDetection\Detection\AttemptRecord;
use OCA\IntrusionDetection\Detection\CommonFacts;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Login\LoginContext;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\Risk\RiskScorer;
use OCA\IntrusionDetection\Signal\FailedLoginAttempt;
use OCA\IntrusionDetection\Signal\IDetector;
use OCA\IntrusionDetection\Signal\ISignal;
use OCA\IntrusionDetection\Signal\SuccessfulLogin;

/**
 * Detects password spraying (concept section 10.2) after each failed
 * password login.
 *
 * - A failed attempt with a password that is already flagged blocks its
 *   address once it tried that password for MIN_NAMES_TO_BLOCK accounts.
 * - Otherwise: attempts with the same password fingerprint within `window`
 *   (at most one hour) for at least `min_names` different login names fire.
 *   The limit is lowered when the failing address has an elevated or high
 *   risk score ({@see RiskScorer::limits()}). The names are only counted
 *   once the cheap bound of {@see AttemptCounters} can reach the limit.
 *   The failing address is blocked, and so is every address that tried the
 *   password for at least MIN_NAMES_TO_BLOCK accounts in the window (at most
 *   MAX_BAN_TARGETS); the fingerprint is flagged for a day.
 *
 * - A successful login with a flagged password ({@see SuccessfulLogin})
 *   is a detection of its own for the account, with the login responses
 *   (extra confirmation, telling the user, a new password). Whether the
 *   login needs confirmation is decided by the step-up reasons, which read
 *   the same flag.
 *
 * @template-implements IDetector<FailedLoginAttempt|SuccessfulLogin>
 */
class PasswordSprayingDetector implements IDetector {
	/** The namespace of its memory cache in {@see Caches} */
	public const CACHE = 'password-spraying';
	public const KINDS = [AttemptKind::PasswordLogin];

	public function __construct(
		private readonly CheckSettings $settings,
		private readonly AttemptMapper $attempts,
		private readonly FlaggedSources $flags,
		private readonly Fingerprinter $fingerprinter,
		private readonly Caches $caches,
		private readonly RiskScorer $risk,
		private readonly AttemptCounters $counters,
	) {
	}

	/**
	 * @param FailedLoginAttempt|SuccessfulLogin $signal
	 * @return \Generator<int, DetectionDraft, ?Detection, void>
	 */
	#[\Override]
	public function detect(#[\SensitiveParameter] ISignal $signal, ModeState $mode): \Generator {
		if ($signal instanceof SuccessfulLogin) {
			yield from $this->success($signal->login);
			return;
		}
		$attempt = $signal->attempt;
		$password = $signal->password;
		$userAgent = $signal->userAgent;
		if ($attempt->kind !== AttemptKind::PasswordLogin || $attempt->passwordCandidates === [] || $password === null || $password === '') {
			return;
		}

		if ($this->flags->isPasswordFlagged($attempt->passwordCandidates)) {
			yield from $this->banJoiningSource($attempt, $userAgent);
			return;
		}

		// At most an hour, as long as attempts are kept (the parameter's maximum).
		$window = $this->settings->paramInt(PasswordSpraying::ID, 'window');
		// Without a flag (Observe, or the response switched off) every further
		// attempt would fire again and re-block every address; one detection
		// per spray and window is enough, later addresses are blocked singly,
		// without counting the spray again. The cache key is derived from the
		// fingerprint and never stored.
		$flags = $mode->acts() && $this->settings->hasResponse(PasswordSpraying::ID, ResponseType::FlagPassword);
		$seenKey = 'spray:' . hash('sha256', $attempt->passwordCandidates[0]);
		if (!$flags && $this->caches->shared(self::CACHE)?->get($seenKey) !== null) {
			if ($mode->acts()) {
				yield from $this->banJoiningSource($attempt, $userAgent);
			}
			return;
		}

		$since = $attempt->time - $window;
		$minNames = $this->settings->paramInt(PasswordSpraying::ID, 'min_names');
		if (!$this->counters->mayReach('pw_fp', $attempt->passwordCandidates, $attempt->time, $this->risk->lowestLimit($minNames))) {
			return;
		}
		$stats = $this->attempts->stats('pw_fp', $attempt->passwordCandidates, self::KINDS, $since);
		$limits = $this->risk->limits($attempt->source, ['min_names' => [$minNames, $stats->distinctNames]]);
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
			facts: new PasswordSprayingFacts(
				rule: PasswordSprayingRule::Spray,
				failures: $stats->failures,
				names: $stats->distinctNames,
				sources: $stats->distinctSources,
				banTargets: count($targets),
				listed: count($perSource),
				common: new CommonFacts(
					first: $stats->first,
					last: $stats->last,
					targets: $this->attempts->distinctUids('pw_fp', $attempt->passwordCandidates, self::KINDS, $since, 20),
					risk: $limits->facts(),
				),
			),
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
		yield $draft;
		if (!$flags) {
			$this->caches->shared(self::CACHE)?->set($seenKey, 1, $window);
		}
	}

	/**
	 * A successful password login: when its password is flagged, a detection
	 * for the account, merged per account, address and hour, with the login
	 * responses.
	 *
	 * @return list<DetectionDraft>
	 */
	private function success(LoginContext $login): array {
		if (!$login->passwordFlagged) {
			return [];
		}
		return [new DetectionDraft(
			checkId: PasswordSpraying::ID,
			source: $login->source,
			uid: $login->uid(),
			facts: new PasswordSprayingFacts(rule: PasswordSprayingRule::Login, client: !$login->interactive),
			merge: DetectionDraft::MERGE_SOURCE_USER,
			userAgent: $login->userAgent,
		)];
	}

	/**
	 * An address that joins a spray already detected: blocked once it tried
	 * the password for MIN_NAMES_TO_BLOCK accounts itself, like the other
	 * addresses of the spray, without evaluating the whole spray again.
	 * Someone who mistyped their own password, which happens to be the
	 * sprayed one, is no target.
	 *
	 * @return \Generator<int, DetectionDraft, ?Detection, void>
	 */
	private function banJoiningSource(#[\SensitiveParameter] AttemptRecord $attempt, ?string $userAgent): \Generator {
		if (!$this->counters->mayReach('ip_key', [$attempt->source->ipKey], $attempt->time, PasswordSpraying::MIN_NAMES_TO_BLOCK)) {
			return;
		}
		$window = $this->settings->paramInt(PasswordSpraying::ID, 'window');
		$own = $this->attempts->statsForSourceWithPasswords($attempt->source->ipKey, $attempt->passwordCandidates, self::KINDS, $attempt->time - $window);
		if ($own->distinctNames < PasswordSpraying::MIN_NAMES_TO_BLOCK) {
			return;
		}
		yield new DetectionDraft(
			checkId: PasswordSpraying::ID,
			source: $attempt->source,
			facts: new PasswordSprayingFacts(rule: PasswordSprayingRule::Flagged, names: $own->distinctNames),
			merge: DetectionDraft::MERGE_SOURCE,
			userAgent: $userAgent,
		);
	}
}
