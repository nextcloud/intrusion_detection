<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

use OCA\IntrusionDetection\Login\CoreSession;
use OCA\IntrusionDetection\Login\SessionMarkers;

/**
 * Where a login's confirmation is kept, as one unit: the session's markers
 * ({@see LoginConfirmation::toMarker()}), and for a login that has not
 * been confirmed, the remembered session on the server with its deadline
 * and code tries ({@see UnconfirmedSessions}), so that the session cannot
 * come back without its state. Only {@see LoginConfirmations} writes here.
 */
class LoginConfirmationStore {
	public function __construct(
		private readonly SessionMarkers $markers,
		private readonly UnconfirmedSessions $unconfirmed,
		private readonly CoreSession $coreSession,
	) {
	}

	/**
	 * The step-up of the current session, if any.
	 */
	public function current(): ?StepUpState {
		$data = $this->markers->get(SessionMarkers::STEP_UP);
		return $data === null ? null : StepUpState::fromArray($data);
	}

	/**
	 * The confirmation of an account's login in this session.
	 */
	public function of(string $uid): LoginConfirmation {
		return LoginConfirmation::fromMarkers($this->markers->all(), $uid);
	}

	/**
	 * Keep a confirmation in the session. A step-up is also remembered on
	 * the server when the session could come back without its state.
	 *
	 * @param bool $resumable whether the session could come back without its state
	 */
	public function put(LoginConfirmation $confirmation, bool $resumable = true): LoginConfirmation {
		$marker = $confirmation->toMarker();
		if ($marker === null) {
			return $confirmation;
		}
		// Without a writable session the login cannot be held back; the error is logged by the session markers.
		if ($this->markers->set($marker[0], $marker[1]) && $confirmation->stepUp !== null && $resumable) {
			$sessionId = $this->sessionId();
			if ($sessionId !== '') {
				$this->unconfirmed->remember($sessionId, $confirmation->uid, $confirmation->stepUp->hasDeadline() ? $confirmation->stepUp : null);
			}
		}
		return $confirmation;
	}

	/**
	 * A changed step-up of the session; a pending one keeps its deadline on
	 * the server too.
	 */
	public function update(StepUpState $stepUp): bool {
		$saved = $this->markers->set(SessionMarkers::STEP_UP, $stepUp->toArray());
		if ($saved && $stepUp->isPending()) {
			$sessionId = $this->sessionId();
			if ($sessionId !== '') {
				$this->unconfirmed->extendDeadline($sessionId, $stepUp->deadline);
			}
		}
		return $saved;
	}

	/**
	 * The session's step-up is over.
	 */
	public function removeStepUp(): void {
		$this->markers->remove(SessionMarkers::STEP_UP);
	}

	/**
	 * The session, or the one a remember-me login came back from, no longer
	 * needs to be remembered on the server.
	 */
	public function forget(#[\SensitiveParameter] ?string $sessionId = null): void {
		$this->unconfirmed->forget($sessionId ?? $this->sessionId());
	}

	/**
	 * Count one try of the session's email code on the server
	 * ({@see UnconfirmedSessions::takeCodeAttempt()}).
	 */
	public function takeCodeAttempt(int $max): ?int {
		return $this->unconfirmed->takeCodeAttempt($this->sessionId(), $max);
	}

	/**
	 * The current session's id, '' without one.
	 */
	public function sessionId(): string {
		return $this->coreSession->sessionId() ?? '';
	}
}
