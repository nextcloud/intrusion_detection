<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Detection;

use OCA\IntrusionDetection\Check\Severity;
use OCA\IntrusionDetection\Net\SourceKey;

/**
 * What a check found, before it is stored and answered.
 *
 * `facts` become the detection's explanation (section 16.4 of the concept):
 * the thresholds in force, the measured values, the targets, and anything
 * else needed to explain the detection later. Facts must never contain a
 * password, a fingerprint, a decoy secret, a share token or a credential.
 */
final class DetectionDraft {
	public const MERGE_NONE = 'none';
	public const MERGE_SOURCE = 'source';
	public const MERGE_USER = 'user';
	public const MERGE_SOURCE_USER = 'source_user';

	/** @var list<SourceKey> */
	private array $extraBanTargets = [];

	/**
	 * @param array<string, mixed> $facts
	 * @param self::MERGE_* $merge which repeated hits within `$mergeWindow` update one row
	 * @param ?int $banLevel force at least this escalation level when banning
	 */
	public function __construct(
		public readonly string $checkId,
		public readonly ?SourceKey $source = null,
		public readonly ?string $uid = null,
		public readonly array $facts = [],
		public readonly ?Severity $severity = null,
		public readonly ?int $shareId = null,
		public readonly string $merge = self::MERGE_NONE,
		public readonly int $mergeWindow = 3600,
		public readonly ?int $banLevel = null,
		public readonly ?string $userAgent = null,
	) {
	}

	/**
	 * Further sources the ban response blocks besides `$source`, for
	 * detections that implicate many addresses (password spraying).
	 */
	public function addBanTarget(SourceKey $target): void {
		$this->extraBanTargets[] = $target;
	}

	/**
	 * @return list<SourceKey>
	 */
	public function banTargets(): array {
		$targets = $this->source !== null ? [$this->source] : [];
		foreach ($this->extraBanTargets as $target) {
			$targets[] = $target;
		}
		$unique = [];
		foreach ($targets as $target) {
			$unique[$target->ipKey] = $target;
		}
		return array_values($unique);
	}

	public function mergeKey(): ?string {
		$parts = match ($this->merge) {
			self::MERGE_SOURCE => [$this->source?->ipKey],
			self::MERGE_USER => [$this->uid],
			self::MERGE_SOURCE_USER => [$this->source?->ipKey, $this->uid],
			default => null,
		};
		if ($parts === null || in_array(null, $parts, true)) {
			return null;
		}
		// Hashed, so the key fits the column whatever the inputs are.
		return hash('sha256', $this->checkId . "\0" . implode("\0", $parts));
	}
}
