<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Config;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\CheckDefinition;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\Checks\DecoyCredential;
use OCA\IntrusionDetection\Check\InvalidParamException;
use OCA\IntrusionDetection\Check\IValidatesParams;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Check\ParamDefinition;
use OCA\IntrusionDetection\Check\ParamType;
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
 */
class Settings {
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
		$check = $this->registry->get($checkId);
		$raw = $this->appConfig->getValueString(Application::APP_ID, Keys::mode($checkId), $check->defaultMode->value);
		return Mode::tryFrom($raw) ?? $check->defaultMode;
	}

	/**
	 * The mode a check runs in right now, after the master switch, learning
	 * mode and missing prerequisites are applied.
	 */
	public function modeState(string $checkId): ModeState {
		$check = $this->registry->get($checkId);
		$configured = $this->configuredMode($checkId);
		if (!$this->isEnabled()) {
			return new ModeState($configured, Mode::Off, ModeState::REASON_DISABLED);
		}
		foreach ($check->requirements as $requirement) {
			if (!$this->prerequisites->isMet($requirement)) {
				return new ModeState($configured, Mode::Off, ModeState::REASON_REQUIREMENT, $requirement);
			}
		}
		if ($configured === Mode::Protect && $this->isLearning() && !$this->definitionActsWhileLearning($check)) {
			return new ModeState($configured, Mode::Observe, ModeState::REASON_LEARNING);
		}
		return new ModeState($configured, $configured);
	}

	public function effectiveMode(string $checkId): Mode {
		return $this->modeState($checkId)->effective;
	}

	/**
	 * @throws InvalidParamException
	 */
	public function setMode(string $checkId, Mode $mode): void {
		$check = $this->registry->get($checkId);
		if ($mode !== Mode::Off) {
			foreach ($check->requirements as $requirement) {
				if (!$this->prerequisites->isMet($requirement)) {
					throw new InvalidParamException('mode_unavailable', ['why' => $requirement->value]);
				}
			}
		}
		$old = $this->configuredMode($checkId);
		$this->appConfig->setValueString(Application::APP_ID, Keys::mode($checkId), $mode->value);
		$this->changed(Keys::mode($checkId), $old->value, $mode->value);
	}

	/**
	 * @return int|float|bool|string|list<string>
	 */
	public function param(string $checkId, string $name): int|float|bool|string|array {
		$definition = $this->registry->get($checkId)->param($name);
		return $this->read(Keys::param($checkId, $name), $definition);
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
		foreach ($this->registry->get($checkId)->params as $param) {
			$values[$param->name] = $this->param($checkId, $param->name);
		}
		return $values;
	}

	/**
	 * @throws InvalidParamException
	 */
	public function setParam(string $checkId, string $name, mixed $value): void {
		$definition = $this->registry->get($checkId)->param($name);
		$value = $definition->validate($value, true);
		$check = $this->registry->check($this->registry->classOf($checkId));
		if ($check instanceof IValidatesParams) {
			$value = $definition->validate($check->validateParam($name, $value), true);
		}
		$old = $this->param($checkId, $name);
		$this->write(Keys::param($checkId, $name), $definition, $value);
		$this->changed(Keys::param($checkId, $name), $old, $this->param($checkId, $name));
	}

	public function resetParam(string $checkId, string $name): void {
		$this->registry->get($checkId)->param($name);
		$old = $this->param($checkId, $name);
		$this->appConfig->deleteKey(Application::APP_ID, Keys::param($checkId, $name));
		$this->changed(Keys::param($checkId, $name), $old, $this->param($checkId, $name));
	}

	/**
	 * @return list<ResponseType>
	 */
	public function responses(string $checkId): array {
		$check = $this->registry->get($checkId);
		$defaults = array_map(static fn (ResponseType $r): string => $r->value, $check->defaultResponses);
		$raw = $this->appConfig->getValueArray(Application::APP_ID, Keys::responses($checkId), $defaults);
		$responses = [];
		foreach ($raw as $value) {
			$response = is_string($value) ? ResponseType::tryFrom($value) : null;
			// Responses the check no longer allows are dropped rather than run.
			if ($response !== null && $check->allowsResponse($response)) {
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
	 * @throws InvalidParamException
	 */
	public function setResponses(string $checkId, array $responses): void {
		$check = $this->registry->get($checkId);
		$values = [];
		foreach ($responses as $response) {
			if (!$check->allowsResponse($response)) {
				throw new InvalidParamException('unknown_response', ['response' => $response->value]);
			}
			$values[] = $response->value;
		}
		$old = $this->responseValues($checkId);
		$this->appConfig->setValueArray(Application::APP_ID, Keys::responses($checkId), array_values(array_unique($values)));
		$this->changed(Keys::responses($checkId), $old, $this->responseValues($checkId));
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
			$this->changed(Keys::param($checkId, $name), $oldParams[$name], $value);
		}
	}

	/**
	 * @return int|float|bool|string|list<string>
	 */
	public function global(string $name): int|float|bool|string|array {
		$definition = $this->globals->get($name) ?? throw new InvalidParamException('unknown_param', ['param' => $name]);
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
	 * @throws InvalidParamException
	 */
	public function setGlobal(string $name, mixed $value): void {
		$definition = $this->globals->get($name) ?? throw new InvalidParamException('unknown_param', ['param' => $name]);
		$value = $definition->validate($value, true);
		if (GlobalSettings::isInternal($name)) {
			$this->write($name, $definition, $value);
			return;
		}
		$owner = GlobalSettings::validatedBy($name);
		if ($owner !== null) {
			$check = $this->registry->check($owner);
			if ($check instanceof IValidatesParams) {
				$value = $definition->validate($check->validateParam($name, $value), true);
			}
		}
		$old = $this->global($name);
		$this->write($name, $definition, $value);
		$this->changed($name, $old, $this->global($name));
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
	private function changed(string $key, int|float|bool|string|array $old, int|float|bool|string|array $new): void {
		if ($old !== $new) {
			$this->dispatcher->dispatchTyped(new SettingChangedEvent($key, $old, $new));
		}
	}

	/**
	 * Whether a check set to Protect acts during learning mode: checks that
	 * only notify always do, decoys when `learning_decoys_act` is on.
	 */
	public function actsWhileLearning(string $checkId): bool {
		return $this->definitionActsWhileLearning($this->registry->get($checkId));
	}

	private function definitionActsWhileLearning(CheckDefinition $check): bool {
		if ($check->onlyNotifies()) {
			return true;
		}
		if (!$check->actsWhileLearning) {
			return false;
		}
		return $check->id !== DecoyCredential::ID || $this->getBool(GlobalSettings::LEARNING_DECOYS_ACT);
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
