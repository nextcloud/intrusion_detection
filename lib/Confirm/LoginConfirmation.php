<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\SessionState\SessionState;

/**
 * Where the confirmation of one session's login stands, in one status
 * ({@see ConfirmationStatus}), with what goes with it: how it was confirmed
 * or proven, the reasons it needed one, since when, and while it has a
 * step-up, the step-up itself ({@see StepUpState}).
 *
 * The session keeps it in three markers, in this precedence: the step-up
 * ({@see SessionState::STEP_UP}), the confirmation of a login that needed
 * one ({@see SessionState::CONFIRMATION}, `by` a method or `none`), and the
 * proof of a login that needed none ({@see SessionState::PROOF}).
 */
final class LoginConfirmation {
	/** The confirmation methods that prove more than the password */
	public const PROOFS = [
		IConfirmationMethod::SECOND_FACTOR,
		IConfirmationMethod::EMAIL_CODE,
		IConfirmationMethod::ADMIN_APPROVAL,
		IConfirmationMethod::KNOWN_DEVICE,
	];
	/** `by` of a login let in without a confirmation */
	public const BY_NONE = 'none';
	/** Set in the confirmation marker of a login an app sending the password opened unconfirmed */
	public const CLIENT_ONLY = 'client';

	/**
	 * @param list<string> $policies the reasons the login needed a confirmation
	 */
	private function __construct(
		public readonly string $uid,
		public readonly ConfirmationStatus $status,
		/** How it was confirmed or proven: an {@see IConfirmationMethod} id */
		public readonly ?string $method = null,
		public readonly array $policies = [],
		/** When it started waiting, or was confirmed, let in or proven */
		public readonly int $since = 0,
		/** Let in unconfirmed from an app sending the password: the session serves apps only */
		public readonly bool $clientOnly = false,
		public readonly ?StepUpState $stepUp = null,
	) {
	}

	public static function none(string $uid): self {
		return new self($uid, ConfirmationStatus::None);
	}

	public static function ofStepUp(StepUpState $stepUp): self {
		return new self($stepUp->uid, ConfirmationStatus::from($stepUp->status), null, $stepUp->policies, $stepUp->started, false, $stepUp);
	}

	/**
	 * @param list<string> $policies
	 */
	public static function confirmed(string $uid, string $method, array $policies, int $at): self {
		return new self($uid, ConfirmationStatus::Confirmed, $method, $policies, $at);
	}

	/**
	 * @param list<string> $policies
	 */
	public static function allowed(string $uid, array $policies, int $at, bool $clientOnly): self {
		return new self($uid, ConfirmationStatus::AllowedUnconfirmed, self::BY_NONE, $policies, $at, $clientOnly);
	}

	public static function proven(string $uid, string $method, int $at): self {
		return new self($uid, ConfirmationStatus::Proven, $method, [], $at);
	}

	/**
	 * The confirmation of an account's login from the session's markers,
	 * as the app has stored them since its first release.
	 *
	 * @param array<string, mixed> $markers all of the session's markers ({@see SessionState::all()})
	 */
	public static function fromMarkers(array $markers, string $uid): self {
		$stepUp = is_array($markers[SessionState::STEP_UP] ?? null) ? StepUpState::fromArray($markers[SessionState::STEP_UP]) : null;
		if ($stepUp !== null && $stepUp->uid === $uid) {
			return self::ofStepUp($stepUp);
		}
		$confirmation = $markers[SessionState::CONFIRMATION] ?? null;
		if (is_array($confirmation) && ($confirmation['uid'] ?? null) === $uid) {
			$by = $confirmation['by'] ?? null;
			$policies = is_array($confirmation['policies'] ?? null) ? array_values(array_filter($confirmation['policies'], 'is_string')) : [];
			$at = is_int($confirmation['at'] ?? null) ? $confirmation['at'] : 0;
			if ($by === self::BY_NONE) {
				return self::allowed($uid, $policies, $at, ($confirmation[self::CLIENT_ONLY] ?? false) === true);
			}
			if (is_string($by) && in_array($by, self::PROOFS, true)) {
				return self::confirmed($uid, $by, $policies, $at);
			}
		}
		$proof = $markers[SessionState::PROOF] ?? null;
		if (is_array($proof) && ($proof['uid'] ?? null) === $uid && is_string($proof['by'] ?? null) && in_array($proof['by'], self::PROOFS, true)) {
			return self::proven($uid, $proof['by'], is_int($proof['at'] ?? null) ? $proof['at'] : 0);
		}
		return self::none($uid);
	}

	/**
	 * The marker this confirmation is kept in, and its stored form; null
	 * for a login that needed nothing.
	 *
	 * @return array{0: string, 1: array<string, mixed>}|null
	 */
	public function toMarker(): ?array {
		return match ($this->status) {
			ConfirmationStatus::Pending, ConfirmationStatus::Refused, ConfirmationStatus::RefusedClient, ConfirmationStatus::Resumed => $this->stepUp === null ? null : [SessionState::STEP_UP, $this->stepUp->toArray()],
			ConfirmationStatus::Confirmed, ConfirmationStatus::AllowedUnconfirmed => [SessionState::CONFIRMATION, array_filter([
				'uid' => $this->uid,
				'by' => $this->method,
				'policies' => $this->policies,
				'at' => $this->since,
				self::CLIENT_ONLY => $this->clientOnly ?: null,
			], static fn (mixed $v): bool => $v !== null)],
			ConfirmationStatus::Proven => [SessionState::PROOF, ['uid' => $this->uid, 'by' => $this->method, 'at' => $this->since]],
			ConfirmationStatus::None => null,
		};
	}

	/**
	 * How much the login proved: {@see SessionConfirmation::UNCONFIRMED}
	 * while it has a step-up or was let in without a confirmation,
	 * {@see SessionConfirmation::PROVEN} when it was confirmed or proved
	 * more, and {@see SessionConfirmation::PASSWORD} otherwise.
	 *
	 * @return SessionConfirmation::UNCONFIRMED|SessionConfirmation::PASSWORD|SessionConfirmation::PROVEN
	 */
	public function level(): string {
		return match ($this->status) {
			ConfirmationStatus::Confirmed, ConfirmationStatus::Proven => SessionConfirmation::PROVEN,
			ConfirmationStatus::None => SessionConfirmation::PASSWORD,
			default => SessionConfirmation::UNCONFIRMED,
		};
	}

	/**
	 * Whether the login needed a confirmation it did not get (yet): it
	 * waits, was refused, came back unconfirmed, or was let in without one.
	 */
	public function isRisky(): bool {
		return $this->level() === SessionConfirmation::UNCONFIRMED;
	}

	/**
	 * How the login history records it: how the login was confirmed, and
	 * its step-up outcome.
	 *
	 * @return array{0: string, 1: ?string} confirmed_by, and step_up (null when nothing was needed)
	 */
	public function historyOutcome(): array {
		return match ($this->status) {
			ConfirmationStatus::Pending => [LoginHistory::CONFIRMED_BY_NONE, LoginHistory::STEP_UP_PENDING],
			ConfirmationStatus::Refused, ConfirmationStatus::RefusedClient => [LoginHistory::CONFIRMED_BY_NONE, LoginHistory::STEP_UP_REFUSED],
			ConfirmationStatus::Resumed => [LoginHistory::CONFIRMED_BY_NONE, LoginHistory::STEP_UP_FAILED],
			ConfirmationStatus::Confirmed => [(string)$this->method, LoginHistory::STEP_UP_CONFIRMED],
			ConfirmationStatus::AllowedUnconfirmed => [LoginHistory::CONFIRMED_BY_NONE, LoginHistory::STEP_UP_ALLOWED],
			ConfirmationStatus::Proven, ConfirmationStatus::None => [LoginHistory::CONFIRMED_BY_NONE, null],
		};
	}
}
