<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Configure;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\IValidatesParams;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Keys;
use OCA\IntrusionDetection\Config\Prerequisites;
use OCA\IntrusionDetection\Definition\InvalidParamException;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\ParamDefinition;
use OCA\IntrusionDetection\Definition\ParamType;
use OCA\IntrusionDetection\Definition\ProtectionLevel;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Event\SettingChangedEvent;
use OCA\IntrusionDetection\State\AppState;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IAppConfig;

/**
 * Validated writes of every setting of the app, and the protection level
 * the limits were last set to.
 *
 * Writes validate against the full definitions of the check registry and
 * the global settings, and throw {@see InvalidParamException}. Every write
 * dispatches a {@see SettingChangedEvent} when the effective value changed.
 */
class SettingsEditor {
	/** The protection level the limits were last set to, see {@see ProtectionLevels}; recommended when unset */
	public const LEVEL_STATE = 'protection_level';

	/** While a protection level is applied, its own writes do not make it "custom" */
	private bool $applyingLevel = false;

	public function __construct(
		private readonly IAppConfig $appConfig,
		private readonly CheckSettings $checks,
		private readonly AppSettings $settings,
		private readonly CheckRegistry $registry,
		private readonly Prerequisites $prerequisites,
		private readonly GlobalSettings $globals,
		private readonly IEventDispatcher $dispatcher,
		private readonly AppState $state,
	) {
	}

	/**
	 * @return bool whether the mode changed
	 * @throws InvalidParamException
	 */
	public function setMode(string $checkId, Mode $mode): bool {
		$this->assertModeAvailable($checkId, $mode);
		$old = $this->checks->configuredMode($checkId);
		$this->appConfig->setValueString(Application::APP_ID, Keys::mode($checkId), $mode->value);
		return $this->changed(Keys::mode($checkId), $old->value, $mode->value);
	}

	/**
	 * @throws InvalidParamException when the mode cannot run on this server
	 */
	private function assertModeAvailable(string $checkId, Mode $mode): void {
		if ($mode === Mode::Off) {
			return;
		}
		foreach ($this->registry->get($checkId)->requirements as $requirement) {
			if (!$this->prerequisites->isMet($requirement)) {
				throw new InvalidParamException('mode_unavailable', ['why' => $requirement->value]);
			}
		}
	}

	/**
	 * Change a check's mode, parameters and responses together: every value
	 * is validated first, so a refused value leaves everything as it was.
	 *
	 * @param array<string, mixed> $params new parameter values by name
	 * @param list<ResponseType>|null $responses
	 * @return array{mode?: string, params?: array<string, int|float|bool|string|list<string>>, responses?: list<string>} what really changed
	 * @throws InvalidParamException
	 */
	public function updateCheck(string $checkId, ?Mode $mode, array $params, ?array $responses): array {
		if ($mode !== null) {
			$this->assertModeAvailable($checkId, $mode);
		}
		$validated = [];
		foreach ($params as $name => $value) {
			$validated[(string)$name] = $this->validatedParam($checkId, (string)$name, $value);
		}
		$responseValues = $responses === null ? null : $this->validatedResponses($checkId, $responses);

		$changes = [];
		if ($mode !== null && $this->setMode($checkId, $mode)) {
			$changes['mode'] = $mode->value;
		}
		foreach ($validated as $name => $value) {
			if ($this->writeParam($checkId, $name, $value)) {
				$changes['params'][$name] = $value;
			}
		}
		if ($responseValues !== null && $this->writeResponses($checkId, $responseValues)) {
			$changes['responses'] = $this->responseValues($checkId);
		}
		return $changes;
	}

	/**
	 * @param bool $reported false for a change the app makes on its own and
	 *                       writes to the audit log itself: it is no administration change
	 * @return bool whether the value changed
	 * @throws InvalidParamException
	 */
	public function setParam(string $checkId, string $name, mixed $value, bool $reported = true): bool {
		return $this->writeParam($checkId, $name, $this->validatedParam($checkId, $name, $value), $reported);
	}

	/**
	 * A parameter value as it would be saved: validated by its definition
	 * and by the check.
	 *
	 * @return int|float|bool|string|list<string>
	 * @throws InvalidParamException
	 */
	public function validatedParam(string $checkId, string $name, mixed $value): int|float|bool|string|array {
		$definition = $this->registry->get($checkId)->param($name);
		$value = $definition->validate($value, true);
		$check = $this->registry->check($this->registry->classOf($checkId));
		if ($check instanceof IValidatesParams) {
			$value = $definition->validate($check->validateParam($name, $value), true);
		}
		return $value;
	}

	/**
	 * @param int|float|bool|string|list<string> $value validated
	 */
	private function writeParam(string $checkId, string $name, int|float|bool|string|array $value, bool $reported = true): bool {
		$definition = $this->registry->get($checkId)->param($name);
		$old = $this->checks->param($checkId, $name);
		$this->write(Keys::param($checkId, $name), $definition, $value);
		return $this->presetChanged($definition, $this->changed(Keys::param($checkId, $name), $old, $this->checks->param($checkId, $name), $reported));
	}

	public function resetParam(string $checkId, string $name): void {
		$definition = $this->registry->get($checkId)->param($name);
		$old = $this->checks->param($checkId, $name);
		$this->appConfig->deleteKey(Application::APP_ID, Keys::param($checkId, $name));
		$this->presetChanged($definition, $this->changed(Keys::param($checkId, $name), $old, $this->checks->param($checkId, $name)));
	}

	/**
	 * @param list<ResponseType> $responses
	 * @return bool whether the responses changed
	 * @throws InvalidParamException
	 */
	public function setResponses(string $checkId, array $responses): bool {
		return $this->writeResponses($checkId, $this->validatedResponses($checkId, $responses));
	}

	/**
	 * @param list<ResponseType> $responses
	 * @return list<string>
	 * @throws InvalidParamException
	 */
	private function validatedResponses(string $checkId, array $responses): array {
		$check = $this->registry->get($checkId);
		$values = [];
		foreach ($responses as $response) {
			if (!$check->allowsResponse($response)) {
				throw new InvalidParamException('unknown_response', ['response' => $response->value]);
			}
			$values[] = $response->value;
		}
		return array_values(array_unique($values));
	}

	/**
	 * @param list<string> $values validated
	 */
	private function writeResponses(string $checkId, array $values): bool {
		$old = $this->responseValues($checkId);
		$this->appConfig->setValueArray(Application::APP_ID, Keys::responses($checkId), $values);
		return $this->changed(Keys::responses($checkId), $old, $this->responseValues($checkId));
	}

	/**
	 * @return list<string>
	 */
	private function responseValues(string $checkId): array {
		return array_map(static fn (ResponseType $r): string => $r->value, $this->checks->responses($checkId));
	}

	/**
	 * Put a check back to its default mode, responses and parameters.
	 */
	public function resetCheck(string $checkId): void {
		$check = $this->registry->get($checkId);
		$oldMode = $this->checks->configuredMode($checkId)->value;
		$oldResponses = $this->responseValues($checkId);
		$oldParams = $this->checks->params($checkId);
		$this->appConfig->deleteKey(Application::APP_ID, Keys::mode($checkId));
		$this->appConfig->deleteKey(Application::APP_ID, Keys::responses($checkId));
		foreach ($check->params as $param) {
			$this->appConfig->deleteKey(Application::APP_ID, Keys::param($checkId, $param->name));
		}
		$this->changed(Keys::mode($checkId), $oldMode, $this->checks->configuredMode($checkId)->value);
		$this->changed(Keys::responses($checkId), $oldResponses, $this->responseValues($checkId));
		foreach ($this->checks->params($checkId) as $name => $value) {
			$this->presetChanged($check->param($name), $this->changed(Keys::param($checkId, $name), $oldParams[$name], $value));
		}
	}

	/**
	 * @param bool $reported false for a change the app makes on its own or
	 *                       writes to the audit log itself: it is no administration change
	 * @return bool whether the value changed
	 * @throws InvalidParamException
	 */
	public function setGlobal(string $name, mixed $value, bool $reported = true): bool {
		return $this->writeGlobal($name, $this->validatedGlobal($name, $value), $reported);
	}

	/**
	 * Change several global settings together: every value is validated
	 * first, so a refused value leaves everything as it was.
	 *
	 * @param array<string, mixed> $values
	 * @return array<string, int|float|bool|string|list<string>> the settings that really changed, with their new values
	 * @throws InvalidParamException
	 */
	public function updateGlobals(array $values): array {
		$validated = [];
		foreach ($values as $name => $value) {
			$name = (string)$name;
			$validated[$name] = $this->validatedGlobal($name, $value);
		}
		$changes = [];
		foreach ($validated as $name => $value) {
			if ($this->writeGlobal($name, $value)) {
				$changes[$name] = $this->settings->value($name);
			}
		}
		return $changes;
	}

	/**
	 * Put a global setting back to its default.
	 */
	public function resetGlobal(string $name): bool {
		$definition = $this->globalDefinition($name);
		$old = $this->settings->value($name);
		$this->appConfig->deleteKey(Application::APP_ID, $name);
		return $this->presetChanged($definition, $this->changed($name, $old, $this->settings->value($name)));
	}

	/**
	 * A global setting's value as it would be saved: validated by its
	 * definition and by the check it belongs to, if any.
	 *
	 * @return int|float|bool|string|list<string>
	 * @throws InvalidParamException
	 */
	public function validatedGlobal(string $name, mixed $value): int|float|bool|string|array {
		$definition = $this->globalDefinition($name);
		$value = $definition->validate($value, true);
		GlobalSettings::checkRule($name, $value);
		foreach ($this->registry->all() as $id => $owner) {
			if (in_array($name, $owner->globals, true)) {
				$check = $this->registry->check($this->registry->classOf($id));
				if ($check instanceof IValidatesParams) {
					$value = $definition->validate($check->validateParam($name, $value), true);
				}
			}
		}
		return $value;
	}

	/**
	 * @param int|float|bool|string|list<string> $value validated
	 */
	private function writeGlobal(string $name, int|float|bool|string|array $value, bool $reported = true): bool {
		$definition = $this->globalDefinition($name);
		$old = $this->settings->value($name);
		$this->write($name, $definition, $value);
		return $this->presetChanged($definition, $this->changed($name, $old, $this->settings->value($name), $reported));
	}

	/**
	 * The protection level the limits were last set to.
	 */
	public function protectionLevel(): ProtectionLevel {
		return ProtectionLevel::tryFrom($this->state->get(self::LEVEL_STATE) ?? '') ?? ProtectionLevel::Recommended;
	}

	/**
	 * Every limit is at its default again.
	 */
	public function resetProtectionLevel(): void {
		$this->state->delete(self::LEVEL_STATE);
	}

	/**
	 * Write the values of a protection level, and the level. The values are
	 * validated already ({@see ProtectionLevels}), so nothing is refused.
	 * The level itself is internal state ({@see AppState}): the values are
	 * the changes, and each of them is reported as such.
	 *
	 * @param array<string, array<string, int>> $checkParams validated values by check id and parameter name
	 * @param array<string, int> $globals validated values by global setting name
	 * @return array{checks: array<string, array<string, int|float|bool|string|list<string>>>, settings: array<string, int|float|bool|string|list<string>>} what really changed
	 */
	public function applyProtectionLevel(ProtectionLevel $level, array $checkParams, array $globals): array {
		$changes = ['checks' => [], 'settings' => []];
		$this->applyingLevel = true;
		try {
			foreach ($checkParams as $checkId => $params) {
				foreach ($params as $name => $value) {
					if ($this->writeParam($checkId, $name, $value)) {
						$changes['checks'][$checkId][$name] = $value;
					}
				}
			}
			foreach ($globals as $name => $value) {
				if ($this->writeGlobal($name, $value)) {
					$changes['settings'][$name] = $value;
				}
			}
		} finally {
			$this->applyingLevel = false;
		}
		$this->state->set(self::LEVEL_STATE, $level->value);
		return $changes;
	}

	/**
	 * A limit or block duration changed by hand makes the protection level "custom".
	 *
	 * @return bool $changed, passed through
	 */
	private function presetChanged(ParamDefinition $definition, bool $changed): bool {
		if ($changed && $definition->preset !== null && !$this->applyingLevel && $this->protectionLevel() !== ProtectionLevel::Custom) {
			$this->state->set(self::LEVEL_STATE, ProtectionLevel::Custom->value);
		}
		return $changed;
	}

	/**
	 * @throws InvalidParamException
	 */
	private function globalDefinition(string $name): ParamDefinition {
		return $this->globals->get($name) ?? throw new InvalidParamException('unknown_param', ['param' => $name]);
	}

	/**
	 * @param int|float|bool|string|list<string> $old
	 * @param int|float|bool|string|list<string> $new
	 */
	private function changed(string $key, int|float|bool|string|array $old, int|float|bool|string|array $new, bool $reported = true): bool {
		if ($old === $new) {
			return false;
		}
		$this->dispatcher->dispatchTyped(new SettingChangedEvent($key, $old, $new, $reported));
		return true;
	}

	/**
	 * @param int|float|bool|string|list<string> $value
	 */
	private function write(string $key, ParamDefinition $definition, int|float|bool|string|array $value): void {
		$app = Application::APP_ID;
		match ($definition->type) {
			ParamType::Int, ParamType::Duration => $this->appConfig->setValueInt($app, $key, (int)$value),
			ParamType::Float => $this->appConfig->setValueFloat($app, $key, (float)$value),
			ParamType::Bool => $this->appConfig->setValueBool($app, $key, (bool)$value),
			ParamType::Choice, ParamType::Json => $this->appConfig->setValueString($app, $key, (string)$value),
			ParamType::StringList, ParamType::CidrList => $this->appConfig->setValueArray($app, $key, (array)$value),
		};
	}
}
