<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\SecondFactorFailed;

use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Db\AttemptMapper;
use OCA\IntrusionDetection\Detection\AttemptRecorder;
use OCA\IntrusionDetection\Detection\CommonFacts;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Login\CoreSession;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\Signal\IDetector;
use OCA\IntrusionDetection\Signal\ISignal;
use OCA\IntrusionDetection\Signal\SecondFactorFailure;
use OCP\ISession;
use Psr\Log\LoggerInterface;

/**
 * Detects a correct password followed by failed second factors (concept
 * section 10.4), after each failed challenge, backup codes included.
 *
 * It fires when any of these holds:
 * - the challenge failed `max_failures` times in this login, counted in the
 *   session and keyed by the token of the session waiting for its second
 *   factor (a new login starts again at zero);
 * - it failed `max_failures_hour` times for this account within an hour,
 *   counted from the recorded attempts, whatever the session;
 * - the address is flagged after an earlier attack: then the first failure
 *   is enough.
 *
 * The detection carries the waiting session's token id, so that
 * kill_session ends exactly that session.
 *
 * @template-implements IDetector<SecondFactorFailure>
 */
class SecondFactorFailedDetector implements IDetector {
	public const SESSION_KEY = 'intrusion_detection.second_factor_failures';
	public const HOUR = 3600;

	public function __construct(
		private readonly CheckSettings $settings,
		private readonly AttemptRecorder $recorder,
		private readonly AttemptMapper $attempts,
		private readonly FlaggedSources $flags,
		private readonly CoreSession $coreSession,
		private readonly ISession $session,
		private readonly LoggerInterface $logger,
	) {
	}

	/**
	 * @param SecondFactorFailure $signal
	 * @return list<DetectionDraft>
	 */
	#[\Override]
	public function detect(#[\SensitiveParameter] ISignal $signal, ModeState $mode): iterable {
		$source = $signal->source;
		$uid = $signal->user->getUID();
		$params = $this->settings->params(SecondFactorFailed::ID);
		$attempt = $this->recorder->record(AttemptKind::SecondFactor, $source, null, $uid);
		$sessionTokenId = $this->coreSession->tokenId();
		$loginFailures = $this->countInSession($sessionTokenId);
		$hourFailures = $this->attempts->stats('uid', [$uid], [AttemptKind::SecondFactor], $attempt->time - self::HOUR)->failures;
		$flag = $this->flags->sourceFlag($source);

		$rules = [];
		if ($flag !== null) {
			$rules[] = SecondFactorFailedRule::Flagged;
		}
		if ($loginFailures >= (int)$params['max_failures']) {
			$rules[] = SecondFactorFailedRule::Login;
		}
		if ($hourFailures >= (int)$params['max_failures_hour']) {
			$rules[] = SecondFactorFailedRule::Hour;
		}
		if ($rules === []) {
			return [];
		}

		return [new DetectionDraft(
			checkId: SecondFactorFailed::ID,
			source: $source,
			uid: $uid,
			facts: new SecondFactorFailedFacts(
				provider: $signal->providerId,
				providerName: $signal->providerName,
				loginFailures: $loginFailures,
				hourFailures: $hourFailures,
				rules: $rules,
				flag: $flag,
				sessionTokenId: $sessionTokenId,
				common: new CommonFacts(first: $attempt->time, last: $attempt->time),
			),
			merge: DetectionDraft::MERGE_SOURCE_USER,
			userAgent: $signal->userAgent,
			sessionTokenId: $sessionTokenId,
		)];
	}

	/**
	 * Count this failure for the login waiting for its second factor.
	 *
	 * @return int failures of this login, this one included
	 */
	private function countInSession(?int $sessionTokenId): int {
		try {
			$stored = $this->session->get(self::SESSION_KEY);
			$count = is_array($stored) && ($stored['token'] ?? null) === $sessionTokenId ? (int)($stored['count'] ?? 0) + 1 : 1;
			$this->session->set(self::SESSION_KEY, ['token' => $sessionTokenId, 'count' => $count]);
			return $count;
		} catch (\Throwable $e) {
			// Without a writable session only the hourly count per account applies.
			$this->logger->warning('Intrusion detection could not count a failed second factor in the session', ['exception' => $e]);
			return 1;
		}
	}
}
