<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

/**
 * The step-up of one session, as kept in the PHP session (concept section
 * 7, "intrusion_detection.step_up"): why the login needs confirmation, when
 * it started, the email code's hash, attempts and resends, and the request
 * for an administrator's approval. Never the code itself.
 *
 * A value: a change is a new state, which only {@see LoginConfirmations}
 * stores.
 */
final class StepUpState {
	/**
	 * @param ConfirmationStatus $status one a step-up has ({@see ConfirmationStatus::isStepUp()})
	 * @param list<string> $policies the policies of the reasons that applied
	 * @param list<string> $methods the confirmation methods offered, in order
	 * @param list<int> $resends when a new code was sent
	 */
	public function __construct(
		public readonly string $uid,
		public readonly ConfirmationStatus $status,
		public readonly array $policies,
		public readonly int $started,
		/** Until when the login may wait; an administrator's approval can extend it */
		public readonly int $deadline,
		/** The address the login came from */
		public readonly ?string $ip = null,
		public readonly array $methods = [],
		public readonly ?string $codeHash = null,
		public readonly int $codeExpires = 0,
		public readonly int $attempts = 0,
		public readonly array $resends = [],
		public readonly ?string $reference = null,
		public readonly ?int $detectionId = null,
		public readonly bool $secondFactorRequested = false,
		/** The request for an administrator's approval of this login */
		public readonly ?int $approvalId = null,
	) {
	}

	public function isPending(): bool {
		return $this->status === ConfirmationStatus::Pending;
	}

	public function hasMethod(string $id): bool {
		return in_array($id, $this->methods, true);
	}

	/**
	 * @param list<string> $methods
	 */
	public function withMethods(array $methods): self {
		return $this->copy(['methods' => $methods]);
	}

	/**
	 * A new email code, or none (null): the earlier one stops working.
	 */
	public function withCode(?string $codeHash, int $codeExpires): self {
		return $this->copy(['codeHash' => $codeHash, 'codeExpires' => $codeHash === null ? 0 : $codeExpires]);
	}

	/**
	 * @param list<int> $resends
	 */
	public function withResends(array $resends): self {
		return $this->copy(['resends' => $resends]);
	}

	public function withAttempts(int $attempts): self {
		return $this->copy(['attempts' => $attempts]);
	}

	public function withSecondFactorRequested(): self {
		return $this->copy(['secondFactorRequested' => true]);
	}

	/**
	 * An administrator was asked; the login may wait as long as the request.
	 */
	public function withApproval(int $approvalId, int $expiresAt): self {
		return $this->copy(['approvalId' => $approvalId, 'deadline' => max($this->deadline, $expiresAt)]);
	}

	public function withDeadline(int $deadline): self {
		return $this->copy(['deadline' => $deadline]);
	}

	/**
	 * @param array<string, mixed> $changes
	 */
	private function copy(array $changes): self {
		$data = $this->toArray();
		$keys = ['detectionId' => 'detection', 'secondFactorRequested' => 'secondFactor', 'approvalId' => 'approval'];
		foreach ($changes as $name => $value) {
			$data[$keys[$name] ?? $name] = $value;
		}
		return self::fromArray($data) ?? throw new \LogicException('A step-up stays valid');
	}

	/**
	 * @return array<string, mixed>
	 */
	public function toArray(): array {
		return [
			'uid' => $this->uid,
			'status' => $this->status->value,
			'policies' => $this->policies,
			'started' => $this->started,
			'deadline' => $this->deadline,
			'ip' => $this->ip,
			'methods' => $this->methods,
			'codeHash' => $this->codeHash,
			'codeExpires' => $this->codeExpires,
			'attempts' => $this->attempts,
			'resends' => $this->resends,
			'reference' => $this->reference,
			'detection' => $this->detectionId,
			'secondFactor' => $this->secondFactorRequested,
			'approval' => $this->approvalId,
		];
	}

	/**
	 * @param array<string, mixed> $data
	 * @return ?self null for anything that is not a valid state
	 */
	public static function fromArray(array $data): ?self {
		$status = is_string($data['status'] ?? null) ? ConfirmationStatus::tryFrom($data['status']) : null;
		if (!is_string($data['uid'] ?? null) || $status === null || !$status->isStepUp()) {
			return null;
		}
		return new self(
			$data['uid'],
			$status,
			self::strings($data['policies'] ?? []),
			self::int($data['started'] ?? 0),
			self::int($data['deadline'] ?? 0),
			is_string($data['ip'] ?? null) ? $data['ip'] : null,
			self::strings($data['methods'] ?? []),
			is_string($data['codeHash'] ?? null) ? $data['codeHash'] : null,
			self::int($data['codeExpires'] ?? 0),
			self::int($data['attempts'] ?? 0),
			self::ints($data['resends'] ?? []),
			is_string($data['reference'] ?? null) ? $data['reference'] : null,
			is_int($data['detection'] ?? null) ? $data['detection'] : null,
			($data['secondFactor'] ?? false) === true,
			is_int($data['approval'] ?? null) ? $data['approval'] : null,
		);
	}

	/**
	 * @return list<string>
	 */
	private static function strings(mixed $value): array {
		return is_array($value) ? array_values(array_filter($value, 'is_string')) : [];
	}

	/**
	 * @return list<int>
	 */
	private static function ints(mixed $value): array {
		return is_array($value) ? array_values(array_filter($value, 'is_int')) : [];
	}

	private static function int(mixed $value): int {
		return is_int($value) ? $value : 0;
	}
}
