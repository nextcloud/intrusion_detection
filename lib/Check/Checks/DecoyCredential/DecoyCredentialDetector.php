<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\DecoyCredential;

use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Decoy\DecoyService;
use OCA\IntrusionDetection\Definition\Severity;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Signal\FailedLogin;
use OCA\IntrusionDetection\Signal\IDetector;
use OCA\IntrusionDetection\Signal\ISignal;

/**
 * Detects the use of a decoy credential (concept section 10.6) in a failed
 * login: the attempted password is looked up by its fingerprint, whatever
 * the login name. A decoy's login name with another password is a weaker
 * hit: high instead of critical, and blocked with the usual escalation.
 * A decoy answers the failed login on its own: nothing else runs.
 *
 * @template-implements IDetector<FailedLogin>
 */
class DecoyCredentialDetector implements IDetector {
	public function __construct(
		private readonly DecoyService $decoys,
	) {
	}

	/**
	 * @param FailedLogin $signal
	 * @return list<DetectionDraft>
	 */
	#[\Override]
	public function detect(#[\SensitiveParameter] ISignal $signal, ModeState $mode): iterable {
		$match = $this->decoys->match($signal->password, $signal->loginName);
		if ($match === null) {
			return [];
		}
		[$decoy, $bySecret] = $match;
		$this->decoys->triggered($decoy);
		return [new DetectionDraft(
			checkId: DecoyCredential::ID,
			source: $signal->source,
			facts: new DecoyCredentialFacts(
				decoy: $decoy->getId(),
				label: $decoy->getLabel(),
				format: $decoy->getFormat(),
				match: $bySecret ? DecoyCredentialMatch::Secret : DecoyCredentialMatch::LoginName,
			),
			severity: $bySecret ? Severity::Critical : Severity::High,
			merge: DetectionDraft::MERGE_SOURCE,
			banLevel: $bySecret ? DecoyCredential::BAN_LEVEL : null,
			userAgent: $signal->userAgent,
			final: true,
		)];
	}
}
