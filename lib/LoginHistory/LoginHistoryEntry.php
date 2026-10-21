<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\LoginHistory;

/**
 * One successful login of the login history.
 */
final class LoginHistoryEntry {
	public function __construct(
		public readonly int $id,
		public readonly string $uid,
		public readonly int $createdAt,
		public readonly ?string $ip,
		public readonly ?string $netKey,
		public readonly ?string $userAgent,
		/** One of {@see LoginHistory::METHODS} */
		public readonly string $method,
		public readonly bool $knownDevice,
		/** One of {@see LoginHistory::CONFIRMED_BY} */
		public readonly string $confirmedBy,
		/** Null when no extra confirmation was needed; else one of {@see LoginHistory::STEP_UP} */
		public readonly ?string $stepUp,
		public readonly ?int $sessionTokenId,
	) {
	}

	/**
	 * @param array<string, mixed> $row
	 */
	public static function fromRow(array $row): self {
		return new self(
			(int)$row['id'],
			(string)$row['uid'],
			(int)$row['created_at'],
			isset($row['ip']) ? (string)$row['ip'] : null,
			isset($row['net_key']) ? (string)$row['net_key'] : null,
			isset($row['user_agent']) ? (string)$row['user_agent'] : null,
			(string)$row['method'],
			(bool)($row['known_device'] ?? false),
			(string)$row['confirmed_by'],
			isset($row['step_up']) ? (string)$row['step_up'] : null,
			isset($row['session_token_id']) ? (int)$row['session_token_id'] : null,
		);
	}

	/**
	 * @return array{id: int, uid: string, createdAt: int, ip: ?string, network: ?string, userAgent: ?string, method: string, knownDevice: bool, confirmedBy: string, stepUp: ?string, sessionTokenId: ?int}
	 */
	public function toArray(): array {
		return [
			'id' => $this->id,
			'uid' => $this->uid,
			'createdAt' => $this->createdAt,
			'ip' => $this->ip,
			'network' => $this->netKey,
			'userAgent' => $this->userAgent,
			'method' => $this->method,
			'knownDevice' => $this->knownDevice,
			'confirmedBy' => $this->confirmedBy,
			'stepUp' => $this->stepUp,
			'sessionTokenId' => $this->sessionTokenId,
		];
	}
}
