<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Risk;

/**
 * The count limits one rule of a login-failure check applies to an
 * address, after its risk score lowered them ({@see RiskScorer::limits()}),
 * with the values measured against them. A rule fires when every measured
 * value reaches its limit.
 */
final class RiskLimits {
	/** The detection fact that lists the lowered limits */
	public const FACTS_KEY = 'loweredLimits';

	/**
	 * @param array<string, int> $plain the limits as configured, by parameter name
	 * @param array<string, int> $effective the limits for this address
	 * @param array<string, int> $measured
	 * @param ?RiskAssessment $risk the score, when it was needed to decide
	 */
	public function __construct(
		private readonly array $plain,
		private readonly array $effective,
		private readonly array $measured,
		public readonly ?RiskAssessment $risk,
	) {
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
	 * What the detection stores about the lowered limits: the score and,
	 * per lowered limit, the configured and the applied value. Nothing when
	 * no limit was lowered.
	 *
	 * @return array<string, mixed>
	 */
	public function facts(): array {
		if (!$this->isLowered() || $this->risk === null) {
			return [];
		}
		$lowered = [];
		foreach ($this->effective as $name => $limit) {
			if ($limit !== $this->plain[$name]) {
				$lowered[$name] = ['plain' => $this->plain[$name], 'effective' => $limit];
			}
		}
		return [RiskAssessment::FACTS_KEY => $this->risk->toArray(), self::FACTS_KEY => $lowered];
	}
}
