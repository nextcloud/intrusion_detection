<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\AdminChange;

use OCP\IL10N;

/**
 * A decision on a request for approval was refused, or a change waits for
 * one. Carries a machine-readable reason, so the admin API and occ show the
 * same message.
 */
final class ApprovalException extends \RuntimeException {
	public const NOT_FOUND = 'not_found';
	public const NOT_PENDING = 'not_pending';
	public const EXPIRED = 'expired';
	public const REQUESTER = 'requester';
	public const SUBJECT = 'subject';
	public const NOT_ADMIN = 'not_admin';
	public const SUBJECT_MISSING = 'subject_missing';
	public const GROUP_MISSING = 'group_missing';
	/** The deciding administrator's own login was allowed without a confirmation */
	public const UNCONFIRMED = 'unconfirmed';
	/** A change waits for the approval of a second administrator */
	public const HELD = 'approval_requested';
	/** A change needs the approval of a second administrator, and there is none */
	public const HELD_NO_APPROVER = 'no_approver';
	/** Too many requests are pending, so this one was not stored */
	public const TOO_MANY = 'too_many_requests';

	public function __construct(
		public readonly string $reason,
	) {
		parent::__construct($reason);
	}

	public function describe(IL10N $l): string {
		return match ($this->reason) {
			self::NOT_FOUND => $l->t('There is no such request.'),
			self::NOT_PENDING => $l->t('This request was already decided.'),
			self::EXPIRED => $l->t('This request has expired.'),
			self::REQUESTER => $l->t('The administrator who asked cannot approve their own request. Another administrator must do it.'),
			self::SUBJECT => $l->t('An account cannot decide on a request about itself.'),
			self::NOT_ADMIN => $l->t('Only another member of the admin group can decide on this request.'),
			self::SUBJECT_MISSING => $l->t('The account no longer exists.'),
			self::GROUP_MISSING => $l->t('The group no longer exists.'),
			self::UNCONFIRMED => $l->t('Your own login was not confirmed, so you cannot approve requests from this session. Log in again and confirm it, or ask another administrator.'),
			self::HELD => $l->t('This change switches off the approval of new administrators, so a second administrator must approve it. The other administrators were asked; the change is made once one of them approves.'),
			self::HELD_NO_APPROVER => $l->t('This change switches off the approval of new administrators, so a second administrator must approve it, but there is no other administrator. Make the change with occ on the server instead.'),
			self::TOO_MANY => $l->t('Too many requests are waiting for approval, so this one was not stored. Decide the open requests first.'),
			default => $l->t('The request cannot be decided.'),
		};
	}
}
