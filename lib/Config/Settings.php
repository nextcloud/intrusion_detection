<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Config;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\InvalidParamException;
use OCA\IntrusionDetection\Check\IValidatesParams;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Check\ParamDefinition;
use OCA\IntrusionDetection\Check\ParamType;
use OCA\IntrusionDetection\Check\Requirement;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Event\SettingChangedEvent;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IAppConfig;

/**
 * Typed, validated access to every setting of the app.
 *
 * Reads never throw: a stored value that no longer validates (for example
 * after a definition's range changed) falls back to the default. Writes
 * validate and throw {@see InvalidParamException}. Every write of a setting
 * that is not internal state dispatches a {@see SettingChangedEvent} when the
 * effective value changed.
 *
 * Reads take the definitions from {@see LexiconData}, so that reading a
 * setting builds no check and no other setting. Writes validate against the
 * full definitions of the check registry and the global settings.
 *
 * @psalm-import-type CheckSpec from LexiconData
 * @psalm-import-type ParamSpec from LexiconData
 */
class Settings {
	/** @var array<string, ParamDefinition> read definitions by config key */
	private array $definitions = [];
	/** While a protection level is applied, its own writes do not make it "custom" */
	private bool $applyingLevel = false;

	public function __construct(
		private readonly IAppConfig $appConfig,
		private readonly CheckRegistry $registry,
		private readonly ITimeFactory $timeFactory,
		private readonly Prerequisites $prerequisites,
		private readonly GlobalSettings $globals,
		private readonly IEventDispatcher $dispatcher,
	) {
	}

	public function isEnabled(): bool {
		return $this->getBool(GlobalSettings::ENABLED);
	}

	/**
	 * Whether users see their security events in their own security settings.
	 */
	public function personalPageEnabled(): bool {
		return $this->isEnabled() && $this->getBool(GlobalSettings::PERSONAL_PAGE_ENABLED);
	}

	public function learningUntil(): int {
		return $this->getInt(GlobalSettings::LEARNING_UNTIL);
	}

	public function isLearning(): bool {
		return $this->learningUntil() > $this->timeFactory->getTime();
	}

	/**
	 * The mode the admin chose for a check.
	 */
	public function configuredMode(string $checkId): Mode {
		$default = Mode::from($this->check($checkId)['mode']);
		$raw = $this->appConfig->getValueString(Application::APP_ID, Keys::mode($checkId), $default->value);
		return Mode::tryFrom($raw) ?? $default;
	}

	/**
	 * The mode a check runs in right now, after the master switch, learning
	 * mode and missing prerequisites are applied.
	 */
	public function modeState(string $checkId): ModeState {
		$check = $this->check($checkId);
		$configured = $this->configuredMode($checkId);
		if (!$this->isEnabled()) {
			return new ModeState($configured, Mode::Off, ModeState::REASON_DISABLED);
		}
		foreach ($check['requirements'] as $value) {
			$requirement = Requirement::from($value);
			if (!$this->prerequisites->isMet($requirement)) {
				return new ModeState($configured, Mode::Off, ModeState::REASON_REQUIREMENT, $requirement);
			}
		}
		if ($configured === Mode::Protect && $this->isLearning() && !self::specActsWhileLearning($check)) {
			return new ModeState($configured, Mode::Observe, ModeState::REASON_LEARNING);
		}
		return new ModeState($configured, $configured);
	}

	public function effectiveMode(string $checkId): Mode {
		return $this->modeState($checkId)->effective;
	}

	/**
	 * @return bool whether the mode changed
	 * @throws InvalidParamException
	 */
	public function setMode(string $checkId, Mode $mode): bool {
		$this->assertModeAvailable($checkId, $mode);
		$old = $this->configuredMode($checkId);
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
	 * @return int|float|bool|string|list<string>
	 */
	public function param(string $checkId, string $name): int|float|bool|string|array {
		$key = Keys::param($checkId, $name);
		$definition = $this->definitions[$key] ??= self::fromSpec($name, $this->check($checkId)['params'][$name] ?? null)
			?? $this->registry->get($checkId)->param($name);
		return $this->read($key, $definition);
	}

	public function paramInt(string $checkId, string $name): int {
		return (int)$this->param($checkId, $name);
	}

	public function paramFloat(string $checkId, string $name): float {
		return (float)$this->param($checkId, $name);
	}

	public function paramBool(string $checkId, string $name): bool {
		return (bool)$this->param($checkId, $name);
	}

	/**
	 * @return list<string>
	 */
	public function paramList(string $checkId, string $name): array {
		$value = $this->param($checkId, $name);
		return is_array($value) ? $value : [];
	}

	/**
	 * @return array<string, int|float|bool|string|list<string>> every parameter of the check with its current value
	 */
	public function params(string $checkId): array {
		$values = [];
		foreach (array_keys($this->check($checkId)['params']) as $name) {
			$values[$name] = $this->param($checkId, $name);
		}
		return $values;
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
		$old = $this->param($checkId, $name);
		$this->write(Keys::param($checkId, $name), $definition, $value);
		return $this->presetChanged($definition, $this->changed(Keys::param($checkId, $name), $old, $this->param($checkId, $name), $reported));
	}

	public function resetParam(string $checkId, string $name): void {
		$definition = $this->registry->get($checkId)->param($name);
		$old = $this->param($checkId, $name);
		$this->appConfig->deleteKey(Application::APP_ID, Keys::param($checkId, $name));
		$this->presetChanged($definition, $this->changed(Keys::param($checkId, $name), $old, $this->param($checkId, $name)));
	}

	/**
	 * @return list<ResponseType>
	 */
	public function responses(string $checkId): array {
		$check = $this->check($checkId);
		$raw = $this->appConfig->getValueArray(Application::APP_ID, Keys::responses($checkId), $check['responses']);
		$responses = [];
		foreach ($raw as $value) {
			$response = is_string($value) ? ResponseType::tryFrom($value) : null;
			// Responses the check no longer allows are dropped rather than run.
			if ($response !== null && in_array($response->value, $check['allowed'], true)) {
				$responses[] = $response;
			}
		}
		return $responses;
	}

	public function hasResponse(string $checkId, ResponseType $response): bool {
		return in_array($response, $this->responses($checkId), true);
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
		return array_map(static fn (ResponseType $r): string => $r->value, $this->responses($checkId));
	}

	/**
	 * Put a check back to its default mode, responses and parameters.
	 */
	public function resetCheck(string $checkId): void {
		$check = $this->registry->get($checkId);
		$oldMode = $this->configuredMode($checkId)->value;
		$oldResponses = $this->responseValues($checkId);
		$oldParams = $this->params($checkId);
		$this->appConfig->deleteKey(Application::APP_ID, Keys::mode($checkId));
		$this->appConfig->deleteKey(Application::APP_ID, Keys::responses($checkId));
		foreach ($check->params as $param) {
			$this->appConfig->deleteKey(Application::APP_ID, Keys::param($checkId, $param->name));
		}
		$this->changed(Keys::mode($checkId), $oldMode, $this->configuredMode($checkId)->value);
		$this->changed(Keys::responses($checkId), $oldResponses, $this->responseValues($checkId));
		foreach ($this->params($checkId) as $name => $value) {
			$this->presetChanged($check->param($name), $this->changed(Keys::param($checkId, $name), $oldParams[$name], $value));
		}
	}

	/**
	 * @return int|float|bool|string|list<string>
	 */
	public function global(string $name): int|float|bool|string|array {
		$definition = $this->definitions[$name] ??= self::fromSpec($name, LexiconData::GLOBALS[$name] ?? null) ?? $this->globalDefinition($name);
		return $this->read($name, $definition);
	}

	public function getInt(string $name): int {
		return (int)$this->global($name);
	}

	public function getBool(string $name): bool {
		return (bool)$this->global($name);
	}

	/**
	 * A ParamType::Json setting, decoded. Invalid stored JSON reads as empty.
	 *
	 * @return array<array-key, mixed>
	 */
	public function getJson(string $name): array {
		$decoded = json_decode((string)$this->global($name), true);
		return is_array($decoded) ? $decoded : [];
	}

	/**
	 * @param bool $reported false for a change the app makes on its own or
	 *                       writes to the audit log itself: it is no administration change
	 * @return bool whether the value changed (always false for internal state)
	 * @throws InvalidParamException
	 */
	public function setGlobal(string $name, mixed $value, bool $reported = true): bool {
		$value = $this->validatedGlobal($name, $value);
		if (GlobalSettings::isInternal($name)) {
			$this->write($name, $this->globalDefinition($name), $value);
			return false;
		}
		return $this->writeGlobal($name, $value, $reported);
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
			if (GlobalSettings::isInternal($name)) {
				throw new InvalidParamException('unknown_param', ['param' => $name]);
			}
			$validated[$name] = $this->validatedGlobal($name, $value);
		}
		$changes = [];
		foreach ($validated as $name => $value) {
			if ($this->writeGlobal($name, $value)) {
				$changes[$name] = $this->global($name);
			}
		}
		return $changes;
	}

	/**
	 * Put a global setting back to its default.
	 */
	public function resetGlobal(string $name): bool {
		$this->globalDefinition($name);
		if (GlobalSettings::isInternal($name)) {
			$this->appConfig->deleteKey(Application::APP_ID, $name);
			return false;
		}
		$old = $this->global($name);
		$this->appConfig->deleteKey(Application::APP_ID, $name);
		return $this->presetChanged($this->globalDefinition($name), $this->changed($name, $old, $this->global($name)));
	}

	/**
	 * A global setting's value as it would be saved: validated by its
	 * definition and by the check that owns it.
	 *
	 * @return int|float|bool|string|list<string>
	 * @throws InvalidParamException
	 */
	public function validatedGlobal(string $name, mixed $value): int|float|bool|string|array {
		$definition = $this->globalDefinition($name);
		$value = $definition->validate($value, true);
		$owner = GlobalSettings::isInternal($name) ? null : GlobalSettings::validatedBy($name);
		if ($owner !== null) {
			$check = $this->registry->check($owner);
			if ($check instanceof IValidatesParams) {
				$value = $definition->validate($check->validateParam($name, $value), true);
			}
		}
		return $value;
	}

	/**
	 * @param int|float|bool|string|list<string> $value validated
	 */
	private function writeGlobal(string $name, int|float|bool|string|array $value, bool $reported = true): bool {
		$definition = $this->globalDefinition($name);
		$old = $this->global($name);
		$this->write($name, $definition, $value);
		return $this->presetChanged($definition, $this->changed($name, $old, $this->global($name), $reported));
	}

	/**
	 * The protection level the limits were last set to.
	 */
	public function protectionLevel(): ProtectionLevel {
		return ProtectionLevel::tryFrom((string)$this->global(GlobalSettings::PROTECTION_LEVEL)) ?? ProtectionLevel::Recommended;
	}

	/**
	 * Write the values of a protection level, and the level. The values are
	 * validated already ({@see ProtectionLevels}), so nothing is refused.
	 * The level itself is internal state: the values are the changes, and
	 * each of them is reported as such.
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
		$this->setGlobal(GlobalSettings::PROTECTION_LEVEL, $level->value);
		return $changes;
	}

	/**
	 * A limit or block duration changed by hand makes the protection level "custom".
	 *
	 * @return bool $changed, passed through
	 */
	private function presetChanged(ParamDefinition $definition, bool $changed): bool {
		if ($changed && $definition->preset !== null && !$this->applyingLevel && $this->protectionLevel() !== ProtectionLevel::Custom) {
			$this->setGlobal(GlobalSettings::PROTECTION_LEVEL, ProtectionLevel::Custom->value);
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
	 * Ban durations in seconds for the escalation levels 1, 2 and 3.
	 *
	 * @return array{1: int, 2: int, 3: int}
	 */
	public function banDurations(): array {
		return [
			1 => $this->getInt(GlobalSettings::BAN_DURATION_1),
			2 => $this->getInt(GlobalSettings::BAN_DURATION_2),
			3 => $this->getInt(GlobalSettings::BAN_DURATION_3),
		];
	}

	/**
	 * Values for the `{name}` placeholders of explanation texts: the check's
	 * parameters, and every global setting.
	 *
	 * @return array<string, int|float|bool|string|list<string>>
	 */
	public function placeholderValues(?string $checkId = null): array {
		$values = [];
		foreach ($this->globals->all() as $name => $definition) {
			if (!GlobalSettings::isInternal($name)) {
				$values[$name] = $this->read($name, $definition);
			}
		}
		if ($checkId !== null) {
			$values = array_merge($values, $this->params($checkId));
		}
		return $values;
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
	 * Whether a check set to Protect acts during learning mode: checks that
	 * only notify always do, and so do decoys and reserved names.
	 */
	public function actsWhileLearning(string $checkId): bool {
		return self::specActsWhileLearning($this->check($checkId));
	}

	/**
	 * @param CheckSpec $check
	 */
	private static function specActsWhileLearning(array $check): bool {
		return $check['onlyNotifies'] || $check['learning'];
	}

	/**
	 * @return CheckSpec
	 * @throws InvalidParamException for an unknown check
	 */
	private function check(string $checkId): array {
		return LexiconData::CHECKS[$checkId] ?? throw new InvalidParamException('unknown_check', ['check' => $checkId]);
	}

	/**
	 * A definition to read with, built from its static data; null when its
	 * items need a validator of their own, which only the full definition has.
	 *
	 * @param ?ParamSpec $spec
	 */
	private static function fromSpec(string $name, ?array $spec): ?ParamDefinition {
		if ($spec === null || isset($spec['validator'])) {
			return null;
		}
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

	/**
	 * @return int|float|bool|string|list<string>
	 */
	private function read(string $key, ParamDefinition $definition): int|float|bool|string|array {
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
