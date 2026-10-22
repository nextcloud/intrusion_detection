<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Repair;

use OCA\IntrusionDetection\AdminChange\ConfigWatch;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\BackgroundJob\Cleanup;
use OCA\IntrusionDetection\Blocklist\StateStore;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffingDetector;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Confirm\ConfirmationCoverage;
use OCA\IntrusionDetection\Detection\DetectionTotals;
use OCA\IntrusionDetection\Learning\LearningService;
use OCA\IntrusionDetection\Notification\DigestSender;
use OCA\IntrusionDetection\StaleCredential\StaleCredentialSweep;
use OCA\IntrusionDetection\State\AppState;
use OCA\IntrusionDetection\Traps\TrapNameCollisions;
use OCP\IAppConfig;
use OCP\Migration\IOutput;
use OCP\Migration\IRepairStep;

/**
 * Moves the internal state that earlier versions kept in the app config to
 * {@see AppState}, under the same names, and deletes the app config keys.
 * A value already in AppState is kept.
 *
 * Runs after every upgrade and does nothing once the keys are gone.
 */
class MoveInternalState implements IRepairStep {
	/** The names, as app config keys before and as AppState names now */
	public const MOVED = [
		AppState::INSTALLED_AT,
		LearningService::STARTED_STATE,
		LearningService::NOTICE_STATE,
		StateStore::STATE,
		CredentialStuffingDetector::DISTRIBUTED_UNTIL_STATE,
		CredentialStuffingDetector::DISTRIBUTED_DETECTED_AT_STATE,
		CredentialStuffingDetector::DISTRIBUTED_DETECTION_STATE,
		ConfigWatch::BASELINE_STATE,
		DigestSender::STATE,
		DetectionTotals::RETIRED_STATE,
		Cleanup::BANS_FLAGGED_STATE,
		ConfirmationCoverage::USERS_STATE,
		TrapNameCollisions::STATE,
		Settings::LEVEL_STATE,
		StaleCredentialSweep::STATE,
	];

	public function __construct(
		private readonly IAppConfig $appConfig,
		private readonly AppState $state,
	) {
	}

	#[\Override]
	public function getName(): string {
		return 'Move the intrusion detection internal state out of the app config';
	}

	#[\Override]
	public function run(IOutput $output): void {
		$stored = array_intersect($this->appConfig->getKeys(Application::APP_ID), self::MOVED);
		if ($stored === []) {
			return;
		}
		$values = $this->appConfig->getAllValues(Application::APP_ID);
		foreach ($stored as $name) {
			$value = $values[$name] ?? null;
			if ((is_int($value) || is_string($value)) && $this->state->get($name) === null) {
				$this->state->set($name, (string)$value);
			}
			$this->appConfig->deleteKey(Application::APP_ID, $name);
		}
	}
}
