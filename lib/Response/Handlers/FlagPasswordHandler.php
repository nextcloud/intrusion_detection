<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Response\Handlers;

use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Explain\IDescribesAction;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\Response\IResponseHandler;
use OCA\IntrusionDetection\Response\ResponseContext;
use OCA\IntrusionDetection\Response\ResponseOutcome;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IL10N;

/**
 * Flags the password a detection is about, by its fingerprints, for the flag
 * duration (a day by default): further failed attempts with it block their
 * address at once, and successful logins with it need extra confirmation.
 *
 * The fingerprints come from the draft and are written to ids_flags only;
 * the action records how many were flagged, never which.
 */
class FlagPasswordHandler implements IResponseHandler, IDescribesAction {
	public function __construct(
		private readonly FlaggedSources $flags,
		private readonly Settings $settings,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	#[\Override]
	public function type(): ResponseType {
		return ResponseType::FlagPassword;
	}

	#[\Override]
	public function apply(ResponseContext $context): ResponseOutcome {
		$fingerprints = $context->draft->passwordFingerprints();
		if ($fingerprints === []) {
			return ResponseOutcome::skipped(ResponseOutcome::NOTE_NOTHING_TO_DO);
		}
		foreach ($fingerprints as $fingerprint) {
			$this->flags->flagPassword($fingerprint, $context->detection->getId());
		}
		return ResponseOutcome::done(['until' => $this->timeFactory->getTime() + $this->settings->getInt(GlobalSettings::FLAG_DURATION)]);
	}

	#[\Override]
	public function describeAction(array $action, IL10N $l, DateFormatter $dates): array {
		$until = (int)(is_array($action['ref'] ?? null) ? ($action['ref']['until'] ?? 0) : 0);
		return [$until > 0
			? $l->t('The password is remembered as attacked until %s: further failed attempts with it block their address at once, and successful logins with it need extra confirmation.', [$dates->dateTime($until)])
			: $l->t('The password is remembered as attacked for a while.')];
	}
}
