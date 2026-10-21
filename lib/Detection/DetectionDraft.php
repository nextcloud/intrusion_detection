<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Detection;

use OCA\IntrusionDetection\Check\ResponseType;
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
	public const MERGE_SHARE = 'share';
	/** Per address and share */
	public const MERGE_SOURCE_SHARE = 'source_share';
	/** Per account and token: `tokenId`, else `sessionTokenId` */
	public const MERGE_TOKEN = 'token';

	/** @var list<SourceKey> */
	private array $extraBanTargets = [];
	/** @var list<string> */
	private array $passwordFingerprints = [];
	/** @var list<ResponseType> */
	private array $onlyWhenNew = [];

	/**
	 * @param array<string, mixed> $facts
	 * @param self::MERGE_* $merge which repeated hits within `$mergeWindow` update one row (hits of different `rule` facts never do)
	 * @param ?int $banLevel force at least this escalation level when banning
	 * @param ?int $sessionTokenId the id of the session token involved, for the kill_session response
	 * @param ?int $tokenId the id of the app password or token involved, for the revoke_token response
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
		public readonly ?int $sessionTokenId = null,
		public readonly ?int $tokenId = null,
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
	 * Hex password fingerprints for the flag_password response. They are
	 * handed to that response only and never stored with the detection.
	 *
	 * @param list<string> $fingerprints
	 */
	public function setPasswordFingerprints(#[\SensitiveParameter] array $fingerprints): void {
		$this->passwordFingerprints = array_values(array_unique($fingerprints));
	}

	/**
	 * @return list<string>
	 */
	public function passwordFingerprints(): array {
		return $this->passwordFingerprints;
	}

	/**
	 * Run these responses for a new detection only, not for a hit that is
	 * merged into an earlier one. Whether it is merged is decided when it is
	 * stored ({@see \OCA\IntrusionDetection\Response\ResponseEngine::handle()}).
	 */
	public function runOnlyWhenNew(ResponseType ...$responses): void {
		$this->onlyWhenNew = array_values(array_unique([...$this->onlyWhenNew, ...$responses], SORT_REGULAR));
	}

	public function runsOnlyWhenNew(ResponseType $response): bool {
		return in_array($response, $this->onlyWhenNew, true);
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
			self::MERGE_SHARE => [$this->shareId === null ? null : (string)$this->shareId],
			self::MERGE_SOURCE_SHARE => [$this->source?->ipKey, $this->shareId === null ? null : (string)$this->shareId],
			self::MERGE_TOKEN => [$this->uid, ($this->tokenId ?? $this->sessionTokenId) === null ? null : (string)($this->tokenId ?? $this->sessionTokenId)],
			default => null,
		};
		if ($parts === null || in_array(null, $parts, true)) {
			return null;
		}
		// Hits of different rules of a check are different detections.
		$rule = $this->facts['rule'] ?? null;
		$scope = is_string($rule) ? $this->checkId . "\0rule:" . $rule : $this->checkId;
		// Hashed, so the key fits the column whatever the inputs are.
		return hash('sha256', $scope . "\0" . implode("\0", $parts));
	}
}
