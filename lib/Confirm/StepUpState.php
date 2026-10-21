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
 * it started, and the email code's hash, attempts and resends. Never the
 * code itself.
 */
final class StepUpState {
	/** The login waits for its confirmation on the verify page */
	public const PENDING = 'pending';
	/** The login was refused: nothing could confirm it */
	public const REFUSED = 'refused';
	/** An app or script logged in with the password: refused for this session */
	public const REFUSED_CLIENT = 'refused_client';
	/** A session whose login was never confirmed came back without its state: it is ended */
	public const RESUMED = 'resumed';

	/**
	 * @param self::PENDING|self::REFUSED|self::REFUSED_CLIENT|self::RESUMED $status
	 * @param list<string> $policies the policies of the reasons that applied
	 * @param list<string> $methods the confirmation methods offered, in order
	 * @param list<int> $resends when a new code was sent
	 */
	public function __construct(
		public readonly string $uid,
		public readonly string $status,
		public readonly array $policies,
		public readonly int $started,
		public readonly int $deadline,
		/** The address the login came from */
		public readonly ?string $ip = null,
		public array $methods = [],
		public ?string $codeHash = null,
		public int $codeExpires = 0,
		public int $attempts = 0,
		public array $resends = [],
		public ?string $reference = null,
		public ?int $detectionId = null,
		public bool $secondFactorRequested = false,
	) {
	}

	public function isPending(): bool {
		return $this->status === self::PENDING;
	}

	public function hasMethod(string $id): bool {
		return in_array($id, $this->methods, true);
	}

	/**
	 * @return array<string, mixed>
	 */
	public function toArray(): array {
		return [
			'uid' => $this->uid,
			'status' => $this->status,
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
		];
	}

	/**
	 * @param array<string, mixed> $data
	 * @return ?self null for anything that is not a valid state
	 */
	public static function fromArray(array $data): ?self {
		$status = $data['status'] ?? null;
		if (!is_string($data['uid'] ?? null) || !in_array($status, [self::PENDING, self::REFUSED, self::REFUSED_CLIENT, self::RESUMED], true)) {
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
