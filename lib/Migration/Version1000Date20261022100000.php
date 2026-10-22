<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Migration;

use Closure;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Configure\SettingsEditor;
use OCA\IntrusionDetection\Repair\RemoveRetiredSettings;
use OCP\IAppConfig;
use OCP\Migration\IOutput;
use OCP\Migration\SimpleMigrationStep;
use Psr\Log\LoggerInterface;

/**
 * One period for detections, the login history and the security changes:
 * `retention_detections_days` becomes the shorter of itself and
 * `history_retention_days`, whose unset value counts as its default of 90
 * days, so that no personal data is kept longer than before.
 *
 * A migration runs once per instance, so a period an administrator sets
 * later is never changed. {@see RemoveRetiredSettings} deletes the old key.
 */
class Version1000Date20261022100000 extends SimpleMigrationStep {
	public const HISTORY_RETENTION_DEFAULT = 90;

	public function __construct(
		private readonly IAppConfig $appConfig,
		private readonly GlobalSettings $globals,
		private readonly AppSettings $settings,
		private readonly SettingsEditor $editor,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function postSchemaChange(IOutput $output, Closure $schemaClosure, array $options): void {
		$key = RemoveRetiredSettings::HISTORY_RETENTION_DAYS;
		$history = in_array($key, $this->appConfig->getKeys(Application::APP_ID), true)
			? $this->appConfig->getAllValues(Application::APP_ID)[$key] ?? null
			: null;
		$historyDays = is_numeric($history) ? (int)$history : self::HISTORY_RETENTION_DEFAULT;
		$detectionsDays = $this->settings->retentionDays();
		if ($historyDays === $detectionsDays) {
			return;
		}

		$days = max((int)($this->globals->get(GlobalSettings::RETENTION_DETECTIONS_DAYS)?->min ?? 1), min($historyDays, $detectionsDays));
		if ($days !== $detectionsDays) {
			$this->editor->setGlobal(GlobalSettings::RETENTION_DETECTIONS_DAYS, $days, false);
			$message = sprintf('Intrusion detection: Keep records for is now %d days: the login history was kept %d days, and the shorter period wins.', $days, $historyDays);
		} else {
			$message = sprintf('Intrusion detection: Keep records for stays %d days, now also for the login history, which was kept %d days: the shorter period wins.', $days, $historyDays);
		}
		$this->logger->info($message, ['app' => Application::APP_ID]);
		$output->info($message);
	}
}
