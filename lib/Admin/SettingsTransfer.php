<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Admin;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Configure\SettingsEditor;
use OCA\IntrusionDetection\Definition\InvalidParamException;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\App\IAppManager;
use OCP\AppFramework\Utility\ITimeFactory;

/**
 * The global settings an administrator changes on the page, "Export
 * settings as JSON" (for support) and "Reset all settings to defaults" on
 * the Advanced tab. Export and reset cover what an admin configures: every
 * configurable check and every editable global setting. Learning mode and
 * internal state are left alone. Changes are written to the audit log.
 *
 * @psalm-import-type IntrusionDetectionExport from ResponseDefinitions
 */
class SettingsTransfer {
	public const FORMAT = 'nextcloud-intrusion-detection-settings/1';

	public function __construct(
		private readonly CheckRegistry $registry,
		private readonly AppSettings $appSettings,
		private readonly CheckSettings $settings,
		private readonly SettingsEditor $editor,
		private readonly GlobalSettings $globals,
		private readonly GlobalSettingsPresenter $presenter,
		private readonly IAppManager $appManager,
		private readonly ITimeFactory $timeFactory,
		private readonly AuditLogger $audit,
	) {
	}

	/**
	 * Change editable global settings, given as typed (text is parsed, so
	 * "4h" works). Every value is validated before anything is saved.
	 *
	 * @param array<array-key, mixed> $values by setting name
	 * @return array<string, int|float|bool|string|list<string>> the settings that really changed, with their new values
	 * @throws InvalidParamException
	 */
	public function changeSettings(array $values, string $actor): array {
		$parsed = [];
		foreach ($values as $name => $value) {
			$name = (string)$name;
			$definition = $this->globals->get($name);
			if ($definition === null || !$this->presenter->isEditable($name)) {
				throw new InvalidParamException('unknown_param', ['param' => $name]);
			}
			$parsed[$name] = $definition->fromInput($value);
		}
		$changes = $this->editor->updateGlobals($parsed);
		if (array_key_exists(GlobalSettings::ENABLED, $changes)) {
			$this->audit->log('intrusion detection turned %s by %s', [
				'state' => $changes[GlobalSettings::ENABLED] === true ? 'on' : 'off',
				'actor' => $actor,
			]);
		}
		if ($changes !== []) {
			$this->audit->log('settings changed by %s: %s', ['actor' => $actor, 'change' => json_encode($changes)]);
		}
		return $changes;
	}

	/**
	 * @return IntrusionDetectionExport
	 */
	public function export(): array {
		$settings = [];
		foreach (array_keys($this->globals->all()) as $name) {
			if ($this->presenter->isEditable($name)) {
				$settings[$name] = $this->appSettings->value($name);
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
	public function resetAll(string $actor): void {
		foreach ($this->registry->configurable() as $check) {
			$this->editor->resetCheck($check->id);
		}
		foreach (array_keys($this->globals->all()) as $name) {
			if ($this->presenter->isEditable($name)) {
				$this->editor->resetGlobal($name);
			}
		}
		$this->editor->resetProtectionLevel();
		$this->audit->log('all settings reset to defaults by %s', ['actor' => $actor]);
	}
}
