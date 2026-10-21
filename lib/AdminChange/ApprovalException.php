<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\AdminChange;

use OCP\IL10N;

/**
 * A decision on a request for approval was refused. Carries a machine-readable
 * reason, so the admin API and occ show the same message.
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
			default => $l->t('The request cannot be decided.'),
		};
	}
}
