<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Lockdown;

use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCP\AppFramework\Utility\ITimeFactory;

/**
 * Whether lockdown mode is on, and which of its effects apply (concept
 * section 11.14). Read on the paths the effects change: logins, sensitive
 * actions, failed logins and share passwords, reset requests and the login
 * page. Every read comes from the app config, which is loaded for the
 * request anyway: no query.
 *
 * Lockdown is an administrator's explicit decision, so it acts in learning
 * mode too. With intrusion detection switched off, it does nothing.
 * {@see LockdownService} starts, extends and ends it.
 */
class LockdownState {
	public function __construct(
		private readonly Settings $settings,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	public function isActive(): bool {
		$until = $this->until();
		return $until > 0 && $until > $this->timeFactory->getTime() && $this->settings->isEnabled();
	}

	/**
	 * When the lockdown ends, or 0 when none was started. In the past for a
	 * lockdown that ended by itself and was not cleaned up yet.
	 */
	public function until(): int {
		return $this->settings->getInt(GlobalSettings::LOCKDOWN_UNTIL);
	}

	/**
	 * Whether lockdown is on and this effect is switched on.
	 */
	public function applies(LockdownEffect $effect): bool {
		return $this->isActive() && in_array($effect, $this->effects(), true);
	}

	/**
	 * @return list<LockdownEffect> the effects that are switched on
	 */
	public function effects(): array {
		$values = $this->settings->global(GlobalSettings::LOCKDOWN_EFFECTS);
		$effects = [];
		foreach (is_array($values) ? $values : [] as $value) {
			$effect = LockdownEffect::tryFrom($value);
			if ($effect !== null) {
				$effects[] = $effect;
			}
		}
		return $effects;
	}

	/**
	 * What the count limits of the checks are multiplied by now: the
	 * lockdown factor while that effect applies, 1 otherwise.
	 */
	public function limitFactor(): float {
		return $this->applies(LockdownEffect::Limits) ? (float)$this->settings->global(GlobalSettings::LOCKDOWN_FACTOR) : 1.0;
	}

	/**
	 * The per-address limit of wrong share passwords during lockdown, or
	 * null when that effect does not apply.
	 */
	public function sharePasswordLimit(): ?int {
		return $this->applies(LockdownEffect::SharePassword) ? LockdownEffect::SHARE_PASSWORD_LIMIT : null;
	}

	/**
	 * @return array{active: bool, until: int, startedAt: int, startedBy: string, reason: string, id: int, effects: list<string>}
	 */
	public function info(): array {
		$active = $this->isActive();
		return [
			'active' => $active,
			'until' => $active ? $this->until() : 0,
			'startedAt' => $active ? $this->settings->getInt(GlobalSettings::LOCKDOWN_STARTED_AT) : 0,
			'startedBy' => $active ? (string)$this->settings->global(GlobalSettings::LOCKDOWN_STARTED_BY) : '',
			'reason' => $active ? (string)$this->settings->global(GlobalSettings::LOCKDOWN_REASON) : '',
			'id' => $active ? $this->settings->getInt(GlobalSettings::LOCKDOWN_ID) : 0,
			'effects' => array_map(static fn (LockdownEffect $e): string => $e->value, $this->effects()),
		];
	}
}
