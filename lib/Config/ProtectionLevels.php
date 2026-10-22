<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Config;

use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Definition\InvalidParamException;
use OCA\IntrusionDetection\Definition\ProtectionLevel;

/**
 * Sets every check limit and block duration to a protection level in one
 * go. Which parameters a level changes, and how, is declared on their
 * definitions ({@see \OCA\IntrusionDetection\Definition\ParamPreset}); modes and
 * responses are never touched.
 *
 * Every value goes through the same validation as a change by hand, all of
 * them before the first is written, so a refused value changes nothing.
 */
class ProtectionLevels {
	public function __construct(
		private readonly CheckRegistry $registry,
		private readonly GlobalSettings $globals,
		private readonly Settings $settings,
	) {
	}

	/**
	 * The values a level gives: the preset parameters of every check, and
	 * the preset global settings.
	 *
	 * @return array{checks: array<string, array<string, int>>, settings: array<string, int>}
	 */
	public function values(ProtectionLevel $level): array {
		$checks = [];
		foreach ($this->registry->all() as $check) {
			foreach ($check->params as $param) {
				$value = $param->presetValue($level);
				if ($value !== null) {
					$checks[$check->id][$param->name] = $value;
				}
			}
		}
		$settings = [];
		foreach ($this->globals->all() as $name => $definition) {
			$value = $definition->presetValue($level);
			if ($value !== null && !GlobalSettings::isInternal($name)) {
				$settings[$name] = $value;
			}
		}
		return ['checks' => $checks, 'settings' => $settings];
	}

	/**
	 * Set the limits to a level.
	 *
	 * @return array{checks: array<string, array<string, int|float|bool|string|list<string>>>, settings: array<string, int|float|bool|string|list<string>>} what really changed
	 * @throws InvalidParamException for Custom, which is not a set of values, or a value the checks refuse
	 */
	public function apply(ProtectionLevel $level): array {
		if ($level === ProtectionLevel::Custom) {
			throw new InvalidParamException('not_a_choice', ['param' => GlobalSettings::PROTECTION_LEVEL, 'choices' => implode(', ', array_map(static fn (ProtectionLevel $l): string => $l->value, ProtectionLevel::choosable()))]);
		}
		$values = $this->values($level);
		$checks = [];
		foreach ($values['checks'] as $checkId => $params) {
			foreach ($params as $name => $value) {
				$checks[$checkId][$name] = (int)$this->settings->validatedParam($checkId, $name, $value);
			}
		}
		$settings = [];
		foreach ($values['settings'] as $name => $value) {
			$settings[$name] = (int)$this->settings->validatedGlobal($name, $value);
		}
		return $this->settings->applyProtectionLevel($level, $checks, $settings);
	}
}
