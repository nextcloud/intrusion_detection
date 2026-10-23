<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Config;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Definition\InvalidParamException;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\Requirement;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCP\IAppConfig;

/**
 * The settings of each check, read-only: its mode, its parameters and its
 * responses. Writes go through {@see \OCA\IntrusionDetection\Configure\SettingsEditor}.
 *
 * Unknown checks and parameters throw {@see InvalidParamException}.
 *
 * @psalm-import-type CheckSpec from LexiconData
 */
class CheckSettings extends StoredSettings {
	public function __construct(
		IAppConfig $appConfig,
		private readonly AppSettings $app,
		private readonly Prerequisites $prerequisites,
	) {
		parent::__construct($appConfig);
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
		return $this->state($checkId, $this->configuredMode($checkId), $this->app->isEnabled(), $this->app->isLearning());
	}

	/**
	 * The mode a check ran in before one of the app's own settings changed:
	 * a change of the master switch, of learning mode or of the check's own
	 * mode is taken back. A change that silences the check is judged by it.
	 *
	 * @param string $name the name of the changed setting
	 * @param int|float|bool|string|list<string> $old its value before
	 */
	public function modeStateBefore(string $checkId, string $name, int|float|bool|string|array $old, int $now): ModeState {
		$configured = $name === Keys::mode($checkId)
			? (is_string($old) ? Mode::tryFrom($old) : null) ?? Mode::from($this->check($checkId)['mode'])
			: $this->configuredMode($checkId);
		$enabled = $name === GlobalSettings::ENABLED ? $old === true : $this->app->isEnabled();
		$learning = $name === GlobalSettings::LEARNING_UNTIL ? is_int($old) && $old > $now : $this->app->isLearning();
		return $this->state($checkId, $configured, $enabled, $learning);
	}

	private function state(string $checkId, Mode $configured, bool $enabled, bool $learning): ModeState {
		$check = $this->check($checkId);
		if (!$enabled) {
			return new ModeState($configured, Mode::Off, ModeState::REASON_DISABLED);
		}
		foreach ($check['requirements'] as $value) {
			$requirement = Requirement::from($value);
			if (!$this->prerequisites->isMet($requirement)) {
				return new ModeState($configured, Mode::Off, ModeState::REASON_REQUIREMENT, $requirement);
			}
		}
		if ($configured === Mode::Protect && $learning && !self::specActsWhileLearning($check)) {
			return new ModeState($configured, Mode::Observe, ModeState::REASON_LEARNING);
		}
		return new ModeState($configured, $configured);
	}

	public function effectiveMode(string $checkId): Mode {
		return $this->modeState($checkId)->effective;
	}

	/**
	 * Whether a check set to Protect acts during learning mode: checks that
	 * only notify always do, and so do decoys and reserved names.
	 */
	public function actsWhileLearning(string $checkId): bool {
		return self::specActsWhileLearning($this->check($checkId));
	}

	/**
	 * @return int|float|bool|string|list<string>
	 */
	public function param(string $checkId, string $name): int|float|bool|string|array {
		$spec = $this->check($checkId)['params'][$name] ?? throw new InvalidParamException('unknown_param', ['param' => $name]);
		return $this->readSpec(Keys::param($checkId, $name), $name, $spec);
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

	/**
	 * Whether a check asks for extra confirmation of a login now: it acts,
	 * and has the step-up response.
	 */
	public function stepUpActive(string $checkId): bool {
		return $this->modeState($checkId)->acts() && $this->hasResponse($checkId, ResponseType::StepUp);
	}

	public function hasResponse(string $checkId, ResponseType $response): bool {
		return in_array($response, $this->responses($checkId), true);
	}

	/**
	 * Values for the `{name}` placeholders of explanation texts: every
	 * global setting, and the check's parameters.
	 *
	 * @return array<string, int|float|bool|string|list<string>>
	 */
	public function placeholderValues(?string $checkId = null): array {
		$values = $this->app->all();
		if ($checkId !== null) {
			$values = array_merge($values, $this->params($checkId));
		}
		return $values;
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
}
