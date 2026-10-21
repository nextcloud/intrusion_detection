<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

use OCA\IntrusionDetection\Check\Checks\StepUpFailed;
use OCP\AppFramework\Http\Response;
use OCP\IUser;

/**
 * What one kind of confirmation does on the shared confirmation pages
 * ({@see ConfirmationPages}): confirming a login, or a sensitive action in a
 * running session. It says where the confirmation in progress is kept,
 * what completing and failing it does, its routes and its texts.
 */
interface IConfirmationFlow {
	/**
	 * The confirmation in progress of the logged-in user, if any.
	 */
	public function pending(IUser $user): ?StepUpState;

	public function save(StepUpState $pending): void;

	/**
	 * It is confirmed with this method.
	 *
	 * @param string $remember "1" when the user asked to remember the browser
	 */
	public function complete(IUser $user, StepUpState $pending, string $method, string $remember): void;

	/**
	 * It failed: too many wrong codes, an administrator rejected it, or
	 * nobody decided in time.
	 *
	 * @param StepUpFailed::RULE_* $rule
	 */
	public function fail(StepUpState $pending, string $rule): Response;

	/**
	 * The user gave up waiting for an administrator.
	 */
	public function giveUp(IUser $user, StepUpState $pending, string $redirectUrl): Response;

	/**
	 * The route of one of the flow's actions: show, confirm, resend,
	 * secondFactor, requestApproval, approvalStatus, continueApproval or
	 * cancelApproval.
	 */
	public function route(string $action): string;

	/**
	 * Paths that are never continued to: the flow's own pages.
	 *
	 * @return list<string>
	 */
	public function excluded(): array;

	/**
	 * The texts of the code page and the waiting page. `$values` holds the
	 * masked address the code went to (f***@example.com), how long a code is
	 * valid, why a confirmation is needed, and how long the waiting page waits.
	 *
	 * @param array{masked: string, valid: string, because: string, left: string} $values
	 * @return array{title: string, lead: string, leadCode: string, why: ?string, warning: string, waitingLead: string, waitingWarning: string, expires: string, cancel: string}
	 */
	public function texts(StepUpState $pending, array $values): array;

	/**
	 * Whether the user may remember the browser after confirming.
	 */
	public function canRemember(): bool;

	/**
	 * Below the code page: where the user goes instead of confirming.
	 *
	 * @return array{url: string, label: string}
	 */
	public function escape(string $redirectUrl): array;
}
