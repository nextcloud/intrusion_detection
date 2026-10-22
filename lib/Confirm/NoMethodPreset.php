<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Configure\SettingsEditor;
use OCA\IntrusionDetection\Definition\InvalidParamException;

/**
 * The one choice on the admin page for logins that need extra confirmation
 * when the account has no way to confirm: it sets the outcome of every
 * {@see StepUpPolicy} at once.
 *
 * - recommended: the default of each reason ({@see StepUpPolicy::defaultOutcome()});
 * - refuse: every such login is refused;
 * - allow: every such login goes ahead and the user and the administrators
 *   are told; with a leaked password a new one is required, since it must
 *   change anyway.
 *
 * Any other combination, set per reason, is "custom".
 */
class NoMethodPreset {
	public const RECOMMENDED = 'recommended';
	public const REFUSE = 'refuse';
	public const ALLOW = 'allow';
	public const CUSTOM = 'custom';

	/** The presets that can be set, in the order the page offers them */
	public const PRESETS = [self::RECOMMENDED, self::REFUSE, self::ALLOW];

	public function __construct(
		private readonly AppSettings $settings,
		private readonly SettingsEditor $editor,
	) {
	}

	/**
	 * The outcome per setting key a preset stands for.
	 *
	 * @return array<string, string>
	 * @throws InvalidParamException for an unknown preset, including "custom"
	 */
	public static function outcomes(string $preset): array {
		if (!in_array($preset, self::PRESETS, true)) {
			throw new InvalidParamException('not_a_choice', ['param' => 'preset', 'choices' => implode(', ', self::PRESETS)]);
		}
		$outcomes = [];
		foreach (StepUpPolicy::cases() as $policy) {
			$outcomes[$policy->settingKey()] = self::outcome($preset, $policy)->value;
		}
		return $outcomes;
	}

	/**
	 * The preset the stored outcomes match, or "custom".
	 *
	 * @return 'recommended'|'refuse'|'allow'|'custom'
	 */
	public function current(): string {
		$stored = [];
		foreach (StepUpPolicy::cases() as $policy) {
			$stored[$policy->settingKey()] = $this->settings->stepUpNoMethod($policy->value);
		}
		foreach (self::PRESETS as $preset) {
			if (self::outcomes($preset) === $stored) {
				return $preset;
			}
		}
		return self::CUSTOM;
	}

	/**
	 * Write the outcome of every reason. They are validated together, so
	 * nothing is saved when one value is refused.
	 *
	 * @return array<string, int|float|bool|string|list<string>> the settings that really changed, with their new values
	 * @throws InvalidParamException
	 */
	public function apply(string $preset): array {
		return $this->editor->updateGlobals(self::outcomes($preset));
	}

	private static function outcome(string $preset, StepUpPolicy $policy): NoMethodOutcome {
		return match ($preset) {
			self::REFUSE => NoMethodOutcome::Refuse,
			self::ALLOW => $policy === StepUpPolicy::BreachedPassword ? NoMethodOutcome::AllowForceChange : NoMethodOutcome::AllowNotify,
			default => $policy->defaultOutcome(),
		};
	}
}
