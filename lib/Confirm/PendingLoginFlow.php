<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

use OCA\IntrusionDetection\Check\Checks\StepUpFailed\StepUpFailedRule;
use OCA\IntrusionDetection\Confirm\Methods\AdminApprovalMethod;
use OCA\IntrusionDetection\Confirm\Methods\SecondFactorMethod;
use OCA\IntrusionDetection\KnownDevice\KnownDevices;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCP\IRequest;
use OCP\IUser;

/**
 * What a login that waits for its confirmation can do on the verify page:
 * enter the email code, ask for a new one, use the second factor, ask an
 * administrator, or give up. Each step reads the session's step-up, and
 * every change goes through {@see LoginConfirmations}. After a confirmed
 * login the browser is remembered when the user chose so ({@see KnownDevices}).
 */
class PendingLoginFlow {
	public function __construct(
		private readonly LoginConfirmations $confirmations,
		private readonly ConfirmationPolicy $policy,
		private readonly EmailCodes $codes,
		private readonly KnownDevices $knownDevices,
		private readonly RemoteAddressResolver $addresses,
		private readonly IRequest $request,
	) {
	}

	/**
	 * The session's step-up, when it is this account's.
	 */
	public function current(IUser $user): ?StepUpState {
		$stepUp = $this->confirmations->current();
		return $stepUp !== null && $stepUp->uid === $user->getUID() ? $stepUp : null;
	}

	/**
	 * The session's step-up, when it is this account's and waits.
	 */
	public function pending(IUser $user): ?StepUpState {
		$stepUp = $this->current($user);
		return $stepUp !== null && $stepUp->isPending() ? $stepUp : null;
	}

	public function enterCode(IUser $user, #[\SensitiveParameter] string $code, bool $rememberDevice): PendingLoginResult {
		$stepUp = $this->pending($user);
		if ($stepUp === null) {
			return PendingLoginResult::NotPending;
		}
		if (!$stepUp->hasMethod(IConfirmationMethod::EMAIL_CODE)) {
			return PendingLoginResult::Unavailable;
		}
		[$result, $stepUp] = $this->codes->verify($stepUp, $code);
		switch ($result) {
			case EmailCodes::VERIFIED:
				return $this->confirmed($user, $stepUp, IConfirmationMethod::EMAIL_CODE, $rememberDevice);
			case EmailCodes::EXHAUSTED:
				$this->confirmations->fail($stepUp, StepUpFailedRule::Attempts);
				return PendingLoginResult::EndedAttempts;
			case EmailCodes::WRONG:
				$this->confirmations->update($stepUp);
				return PendingLoginResult::WrongCode;
			case EmailCodes::EXPIRED:
				return PendingLoginResult::ExpiredCode;
			default:
				return PendingLoginResult::MalformedCode;
		}
	}

	public function resendCode(IUser $user): PendingLoginResult {
		$stepUp = $this->pending($user);
		if ($stepUp === null) {
			return PendingLoginResult::NotPending;
		}
		$hasCode = $stepUp->hasMethod(IConfirmationMethod::EMAIL_CODE);
		if ($hasCode && $this->codes->isGuessLimited($user->getUID())) {
			return PendingLoginResult::TooManyWrongCodes;
		}
		if ($hasCode && $this->codes->isLimited($user)) {
			return PendingLoginResult::TooManyCodes;
		}
		if (!$hasCode || !$this->codes->canResend($stepUp)) {
			return PendingLoginResult::NoResendYet;
		}
		$stepUp = $this->codes->resend($user, $stepUp) ?? $stepUp;
		$this->confirmations->update($stepUp);
		return $stepUp->codeHash !== null ? PendingLoginResult::CodeSent : PendingLoginResult::CodeNotSent;
	}

	/**
	 * Ask the account's second factor at core's challenge, which returns to `$back`.
	 *
	 * @return PendingLoginResult|string the URL of core's challenge, or why there is none
	 */
	public function requestSecondFactor(IUser $user, string $back): PendingLoginResult|string {
		$stepUp = $this->pending($user);
		if ($stepUp === null) {
			return PendingLoginResult::NotPending;
		}
		$method = $this->offered($user, $stepUp, IConfirmationMethod::SECOND_FACTOR);
		if (!$method instanceof SecondFactorMethod) {
			return PendingLoginResult::Unavailable;
		}
		$this->confirmations->update($stepUp->withSecondFactorRequested());
		try {
			return $method->requestChallenge($user, $back);
		} catch (\LogicException) {
			return PendingLoginResult::Unavailable;
		}
	}

	/**
	 * Ask an administrator to approve the login. A login asks once: a
	 * rejected, expired or vanished request ends it.
	 */
	public function requestApproval(IUser $user): PendingLoginResult {
		$stepUp = $this->pending($user);
		if ($stepUp === null) {
			return PendingLoginResult::NotPending;
		}
		$method = $this->approvalMethod($user, $stepUp);
		if ($method === null) {
			return PendingLoginResult::Unavailable;
		}
		if ($stepUp->approvalId !== null) {
			$status = $method->status($user, $stepUp);
			return $this->endByApproval($stepUp, $status === AdminApprovalMethod::STATUS_NONE ? AdminApprovalMethod::STATUS_EXPIRED : $status) ?? PendingLoginResult::Waiting;
		}
		$start = $method->begin($user, $stepUp);
		if ($start->outcome !== IConfirmationMethod::PENDING) {
			return PendingLoginResult::NotStarted;
		}
		$this->confirmations->update($start->state);
		return PendingLoginResult::Waiting;
	}

	/**
	 * Where the login's request for approval stands. Read-only and cheap:
	 * one lookup in the session and one primary-key read.
	 *
	 * @return AdminApprovalMethod::STATUS_*
	 */
	public function approvalStatus(IUser $user): string {
		$stepUp = $this->pending($user);
		$method = $stepUp === null ? null : $this->approvalMethod($user, $stepUp);
		return $method === null || $stepUp === null ? AdminApprovalMethod::STATUS_NONE : $method->status($user, $stepUp);
	}

	/**
	 * Continue a login an administrator decided on.
	 */
	public function continueApproval(IUser $user, bool $rememberDevice): PendingLoginResult {
		$stepUp = $this->pending($user);
		if ($stepUp === null) {
			return PendingLoginResult::NotPending;
		}
		$method = $this->approvalMethod($user, $stepUp);
		$status = $method === null ? AdminApprovalMethod::STATUS_NONE : $method->status($user, $stepUp);
		return $this->endByApproval($stepUp, $status) ?? match ($status) {
			AdminApprovalMethod::STATUS_APPROVED => $this->confirmed($user, $stepUp, IConfirmationMethod::ADMIN_APPROVAL, $rememberDevice),
			AdminApprovalMethod::STATUS_PENDING => PendingLoginResult::Waiting,
			default => PendingLoginResult::Unavailable,
		};
	}

	/**
	 * Give up waiting: the request is withdrawn and the login ends.
	 */
	public function cancel(IUser $user): void {
		$stepUp = $this->pending($user);
		if ($stepUp !== null) {
			$this->approvalMethod($user, $stepUp)?->withdraw($user, $stepUp);
			$this->confirmations->abandon($stepUp);
		}
	}

	/**
	 * End a refused login once it was told why.
	 */
	public function endRefused(): void {
		$this->confirmations->endRefused();
	}

	/**
	 * Whether the login can still be confirmed with this method.
	 */
	public function offers(IUser $user, StepUpState $stepUp, string $methodId): bool {
		return $this->offered($user, $stepUp, $methodId) !== null;
	}

	/**
	 * When the login's request for approval expires, or null without one.
	 */
	public function approvalExpiresAt(IUser $user, StepUpState $stepUp): ?int {
		return $this->approvalMethod($user, $stepUp)?->expiresAt($user, $stepUp);
	}

	private function confirmed(IUser $user, StepUpState $stepUp, string $method, bool $rememberDevice): PendingLoginResult {
		$this->confirmations->complete($stepUp, $method);
		if ($rememberDevice) {
			$this->knownDevices->remember($user, $this->addresses->current(), $this->request->getHeader('User-Agent'));
		}
		return PendingLoginResult::Confirmed;
	}

	/**
	 * End the login when its request for approval was rejected or has expired.
	 *
	 * @param AdminApprovalMethod::STATUS_* $status
	 */
	private function endByApproval(StepUpState $stepUp, string $status): ?PendingLoginResult {
		$ended = match ($status) {
			AdminApprovalMethod::STATUS_REJECTED => PendingLoginResult::EndedRejected,
			AdminApprovalMethod::STATUS_EXPIRED => PendingLoginResult::EndedTimeout,
			default => null,
		};
		$rule = $ended?->endedRule();
		if ($rule !== null) {
			$this->confirmations->fail($stepUp, $rule);
		}
		return $ended;
	}

	private function approvalMethod(IUser $user, StepUpState $stepUp): ?AdminApprovalMethod {
		$method = $this->offered($user, $stepUp, IConfirmationMethod::ADMIN_APPROVAL);
		return $method instanceof AdminApprovalMethod ? $method : null;
	}

	private function offered(IUser $user, StepUpState $stepUp, string $methodId): ?IConfirmationMethod {
		return $this->policy->offered($user, $stepUp, $methodId);
	}
}
