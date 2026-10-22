<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks;

use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Decoy\DecoyService;
use OCA\IntrusionDetection\Definition\Severity;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\ResponseEngine;

/**
 * Detects the use of a decoy credential (concept section 10.6) in a failed
 * login: the attempted password is looked up by its fingerprint, whatever
 * the login name. A decoy's login name with another password is a weaker
 * hit: high instead of critical, and blocked with the usual escalation.
 */
class DecoyCredentialDetector {
	public function __construct(
		private readonly Settings $settings,
		private readonly DecoyService $decoys,
		private readonly ResponseEngine $engine,
	) {
	}

	/**
	 * @return bool whether a decoy was used
	 */
	public function detect(SourceKey $source, string $loginName, #[\SensitiveParameter] ?string $password, ?string $userAgent): bool {
		if (!$this->settings->modeState(DecoyCredential::ID)->runs()) {
			return false;
		}
		$match = $this->decoys->match($password, $loginName);
		if ($match === null) {
			return false;
		}
		[$decoy, $bySecret] = $match;
		$this->decoys->triggered($decoy);
		$this->engine->handle(new DetectionDraft(
			checkId: DecoyCredential::ID,
			source: $source,
			facts: [
				'decoy' => $decoy->getId(),
				'label' => $decoy->getLabel(),
				'format' => $decoy->getFormat(),
				'match' => $bySecret ? DecoyCredential::MATCH_SECRET : DecoyCredential::MATCH_LOGIN_NAME,
			],
			severity: $bySecret ? Severity::Critical : Severity::High,
			merge: DetectionDraft::MERGE_SOURCE,
			banLevel: $bySecret ? DecoyCredential::BAN_LEVEL : null,
			userAgent: $userAgent,
		));
		return true;
	}
}
