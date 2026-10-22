<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Admin;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\App\IAppManager;
use OCP\AppFramework\Utility\ITimeFactory;

/**
 * "Export settings as JSON" (for support) and "Reset all settings to
 * defaults" on the Advanced tab. Both cover what an admin configures:
 * every configurable check and every editable global setting. Learning
 * mode and internal state are left alone.
 *
 * @psalm-import-type IntrusionDetectionExport from ResponseDefinitions
 */
class SettingsTransfer {
	public const FORMAT = 'nextcloud-intrusion-detection-settings/1';

	public function __construct(
		private readonly CheckRegistry $registry,
		private readonly Settings $settings,
		private readonly GlobalSettings $globals,
		private readonly GlobalSettingsPresenter $presenter,
		private readonly IAppManager $appManager,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * @return IntrusionDetectionExport
	 */
	public function export(): array {
		$settings = [];
		foreach (array_keys($this->globals->all()) as $name) {
			if ($this->presenter->isEditable($name)) {
				$settings[$name] = $this->settings->global($name);
			}
		}
		$checks = [];
		foreach ($this->registry->configurable() as $check) {
			$checks[$check->id] = [
				'mode' => $this->settings->configuredMode($check->id)->value,
				'responses' => array_map(static fn (ResponseType $r): string => $r->value, $this->settings->responses($check->id)),
				'params' => $this->settings->params($check->id),
			];
		}
		return [
			'format' => self::FORMAT,
			'version' => $this->appManager->getAppVersion(Application::APP_ID),
			'exportedAt' => $this->timeFactory->getTime(),
			'settings' => $settings,
			'checks' => $checks,
		];
	}

	/**
	 * Put every check and every editable global setting back to its default.
	 */
	public function resetAll(): void {
		foreach ($this->registry->configurable() as $check) {
			$this->settings->resetCheck($check->id);
		}
		foreach (array_keys($this->globals->all()) as $name) {
			if ($this->presenter->isEditable($name)) {
				$this->settings->resetGlobal($name);
			}
		}
		// Every limit is at its default again.
		$this->settings->resetGlobal(GlobalSettings::PROTECTION_LEVEL);
	}
}
