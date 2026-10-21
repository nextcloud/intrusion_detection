<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Payload;

use OCA\IntrusionDetection\Check\Checks\InjectionProbe;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Config\Settings;

/**
 * The injection probe check's settings as the guard and the tester use them.
 *
 * The check has two modes: its own, for visitors who are not logged in, and
 * `authenticated_mode` for logged-in users. The check's own mode is the
 * ceiling: a check set to Observe never acts on logged-in users either, and
 * learning mode turns Protect into Observe for both.
 */
class PayloadSettings {
	public function __construct(
		private readonly Settings $settings,
	) {
	}

	public function anonymousMode(): ModeState {
		return $this->settings->modeState(InjectionProbe::ID);
	}

	public function authenticatedMode(): ModeState {
		$base = $this->settings->modeState(InjectionProbe::ID);
		$chosen = Mode::tryFrom((string)$this->settings->param(InjectionProbe::ID, InjectionProbe::PARAM_AUTHENTICATED_MODE)) ?? Mode::Observe;
		if (!$base->runs() || $chosen === Mode::Off) {
			return new ModeState($chosen, Mode::Off, $base->reason, $base->missing);
		}
		if ($chosen === Mode::Protect && !$base->acts()) {
			return new ModeState($chosen, Mode::Observe, $base->reason);
		}
		if ($chosen === Mode::Observe) {
			return new ModeState($chosen, Mode::Observe, ModeState::REASON_AUTHENTICATED);
		}
		return new ModeState($chosen, $chosen);
	}

	public function rules(): PayloadRules {
		return PayloadRules::build(
			$this->settings->paramInt(InjectionProbe::ID, InjectionProbe::PARAM_MIN_WEIGHT),
			$this->settings->paramInt(InjectionProbe::ID, InjectionProbe::PARAM_MAX_BYTES),
			$this->settings->paramList(InjectionProbe::ID, InjectionProbe::PARAM_DISABLED),
			$this->settings->paramList(InjectionProbe::ID, InjectionProbe::PARAM_CUSTOM),
			$this->settings->paramList(InjectionProbe::ID, InjectionProbe::PARAM_EXCLUDED),
		);
	}
}
