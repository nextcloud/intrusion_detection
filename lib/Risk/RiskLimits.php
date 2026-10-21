<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Risk;

/**
 * The count limits one rule of a login-failure check applies to an
 * address, after its risk score and lockdown mode lowered them
 * ({@see RiskScorer::limits()}), with the values measured against them. A
 * rule fires when every measured value reaches its limit.
 */
final class RiskLimits {
	/** The detection fact that lists the lowered limits */
	public const FACTS_KEY = 'loweredLimits';
	/** The detection fact that says lockdown mode lowered them */
	public const LOCKDOWN_KEY = 'lockdownLimits';

	/**
	 * @param array<string, int> $plain the limits as configured, by parameter name
	 * @param array<string, int> $effective the limits for this address
	 * @param array<string, int> $measured
	 * @param ?RiskAssessment $risk the score, when it was needed to decide
	 * @param float $lockdownFactor what lockdown mode multiplied the limits by; 1 without lockdown
	 * @param array<string, int> $caps the highest each limit could be during lockdown
	 */
	public function __construct(
		private readonly array $plain,
		private readonly array $effective,
		private readonly array $measured,
		public readonly ?RiskAssessment $risk,
		public readonly float $lockdownFactor = 1.0,
		private readonly array $caps = [],
	) {
	}

	/**
	 * Whether lockdown mode lowered a limit.
	 */
	public function byLockdown(): bool {
		return $this->lockdownFactor < 1.0 || $this->caps !== [];
	}

	public function reached(): bool {
		foreach ($this->effective as $name => $limit) {
			if (($this->measured[$name] ?? 0) < $limit) {
				return false;
			}
		}
		return true;
	}

	public function of(string $name): int {
		return $this->effective[$name] ?? $this->plain[$name] ?? 0;
	}

	public function isLowered(): bool {
		return $this->effective !== $this->plain;
	}

	/**
	 * What the detection stores about the lowered limits: the score, whether
	 * lockdown mode lowered them and, per lowered limit, the configured and
	 * the applied value. Nothing when no limit was lowered.
	 *
	 * @return array<string, mixed>
	 */
	public function facts(): array {
		if (!$this->isLowered() || ($this->risk === null && !$this->byLockdown())) {
			return [];
		}
		$lowered = [];
		foreach ($this->effective as $name => $limit) {
			if ($limit !== $this->plain[$name]) {
				$lowered[$name] = ['plain' => $this->plain[$name], 'effective' => $limit];
			}
		}
		$facts = $this->risk === null ? [] : [RiskAssessment::FACTS_KEY => $this->risk->toArray()];
		$facts[self::FACTS_KEY] = $lowered;
		if ($this->byLockdown()) {
			$facts[self::LOCKDOWN_KEY] = ['factor' => $this->lockdownFactor, 'caps' => $this->caps];
		}
		return $facts;
	}
}
