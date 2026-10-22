<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Config;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Definition\InvalidParamException;
use OCA\IntrusionDetection\Definition\ParamDefinition;
use OCA\IntrusionDetection\Definition\ParamType;
use OCP\IAppConfig;

/**
 * Reads stored settings with the definitions of {@see LexiconData}, so that
 * reading a setting builds no check and no setting definition.
 *
 * Reads never throw: a stored value that no longer validates (for example
 * after a definition's range changed) reads as the default.
 *
 * @psalm-import-type ParamSpec from LexiconData
 */
abstract class StoredSettings {
	/** @var array<string, ParamDefinition> by config key */
	private array $definitions = [];

	public function __construct(
		protected readonly IAppConfig $appConfig,
	) {
	}

	/**
	 * @param ParamSpec $spec
	 * @return int|float|bool|string|list<string>
	 */
	protected function readSpec(string $key, string $name, array $spec): int|float|bool|string|array {
		$definition = $this->definitions[$key] ??= self::definition($name, $spec);
		$app = Application::APP_ID;
		$value = match ($definition->type) {
			ParamType::Int, ParamType::Duration => $this->appConfig->getValueInt($app, $key, (int)$definition->default),
			ParamType::Float => $this->appConfig->getValueFloat($app, $key, (float)$definition->default),
			ParamType::Bool => $this->appConfig->getValueBool($app, $key, (bool)$definition->default),
			ParamType::Choice, ParamType::Json => $this->appConfig->getValueString($app, $key, (string)$definition->default),
			ParamType::StringList, ParamType::CidrList => array_values($this->appConfig->getValueArray($app, $key, (array)$definition->default)),
		};
		try {
			return $definition->validate($value);
		} catch (InvalidParamException) {
			return $definition->default;
		}
	}

	/**
	 * A definition to read with, built from its static data. Item
	 * validators of the full definition are left out: whoever uses such a
	 * list skips the items it cannot use.
	 *
	 * @param ParamSpec $spec
	 */
	private static function definition(string $name, array $spec): ParamDefinition {
		return new ParamDefinition(
			$name,
			ParamType::from($spec['type']),
			$spec['default'],
			$spec['min'] ?? null,
			$spec['max'] ?? null,
			$spec['choices'] ?? [],
			$spec['pattern'] ?? null,
			$spec['maxItems'] ?? 200,
			$spec['maxItemLength'] ?? 255,
		);
	}
}
