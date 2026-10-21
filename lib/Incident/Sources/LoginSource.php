<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Incident\Sources;

use OCA\IntrusionDetection\Db\LoginHistoryMapper;
use OCA\IntrusionDetection\Incident\DataCategory;
use OCA\IntrusionDetection\Incident\IncidentQuery;
use OCA\IntrusionDetection\Incident\ITimelineSource;
use OCA\IntrusionDetection\Incident\TimelineEntry;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\LoginHistory\LoginHistoryEntry;
use OCP\IL10N;

/**
 * Successful logins in the period (from `ids_login_history`): of the
 * account, or from the address (an IPv6 address by its /64). A login that
 * was let in although nothing confirmed it is marked as a follow-up.
 */
class LoginSource implements ITimelineSource {
	public const KIND = 'login';

	public function __construct(
		private readonly LoginHistoryMapper $history,
	) {
	}

	#[\Override]
	public function kinds(IL10N $l): array {
		return [self::KIND => $l->t('Logins')];
	}

	#[\Override]
	public function entriesFor(IncidentQuery $query, IL10N $l): iterable {
		$until = $query->until + 1;
		if ($query->isUser()) {
			$rows = $this->history->forUser((string)$query->uid, $query->since, $until, $query->limit, oldestFirst: true);
		} elseif ($query->address !== null) {
			$address = $query->address->family === 6 ? $query->address->netKey : $query->address->ip;
			$rows = $this->history->forAddress($address, $query->since, $until, $query->limit, oldestFirst: true);
		} else {
			return;
		}
		foreach ($rows as $row) {
			yield $this->entry($row, $query, $l);
		}
	}

	private function entry(LoginHistoryEntry $row, IncidentQuery $query, IL10N $l): TimelineEntry {
		$details = [$this->method($row->method, $l)];
		if ($row->userAgent !== null && $row->userAgent !== '') {
			$details[] = $l->t('Client: %s', [$row->userAgent]);
		}
		if ($row->knownDevice) {
			$details[] = $l->t('From a device the account owner chose to remember.');
		}
		$confirmation = $this->confirmation($row, $l);
		if ($confirmation !== null) {
			$details[] = $confirmation;
		}
		$unconfirmed = $row->stepUp === LoginHistory::STEP_UP_ALLOWED;
		return new TimelineEntry(
			id: 'login:' . $row->id,
			at: $row->createdAt,
			kind: self::KIND,
			group: $l->t('Logins'),
			title: match ($row->stepUp) {
				LoginHistory::STEP_UP_REFUSED => $query->isUser() ? $l->t('Login refused') : $l->t('Login of %s refused', [$row->uid]),
				LoginHistory::STEP_UP_FAILED => $query->isUser() ? $l->t('Login not confirmed') : $l->t('Login of %s not confirmed', [$row->uid]),
				default => $query->isUser() ? $l->t('Logged in') : $l->t('%s logged in', [$row->uid]),
			},
			details: $details,
			address: $row->ip,
			accounts: [$row->uid],
			ref: ['type' => 'login', 'id' => (string)$row->id],
			categories: $unconfirmed ? [DataCategory::AccountContent] : [],
			followUp: $unconfirmed ? $l->t('This login was let in although nothing could confirm it. Ask the account owner whether it was them.') : null,
		);
	}

	private function method(string $method, IL10N $l): string {
		return match ($method) {
			LoginHistory::METHOD_PASSWORD => $l->t('With the password, on the login page.'),
			LoginHistory::METHOD_CLIENT_PASSWORD => $l->t('With the password, by an app or script.'),
			LoginHistory::METHOD_APP_PASSWORD => $l->t('With an app password.'),
			LoginHistory::METHOD_TOKEN => $l->t('With an access token.'),
			LoginHistory::METHOD_COOKIE => $l->t('With a remembered browser login.'),
			LoginHistory::METHOD_SSO => $l->t('Through single sign-on.'),
			default => $l->t('In another way.'),
		};
	}

	private function confirmation(LoginHistoryEntry $row, IL10N $l): ?string {
		if ($row->stepUp === null) {
			return null;
		}
		return match ($row->stepUp) {
			LoginHistory::STEP_UP_PENDING => $l->t('Extra confirmation was asked for and not yet given.'),
			LoginHistory::STEP_UP_ALLOWED => $l->t('Extra confirmation was needed, but nothing could confirm it, and the settings let the login in.'),
			LoginHistory::STEP_UP_REFUSED => $l->t('Extra confirmation was needed, but nothing could confirm it, so the login was refused.'),
			LoginHistory::STEP_UP_FAILED => $l->t('Extra confirmation was asked for and not given.'),
			default => match ($row->confirmedBy) {
				'second_factor' => $l->t('Confirmed with the second factor.'),
				'email_code' => $l->t('Confirmed with a code sent by email.'),
				'known_device' => $l->t('Confirmed by a remembered device.'),
				'admin_approval' => $l->t('Confirmed by an administrator.'),
				default => $l->t('Confirmed.'),
			},
		};
	}
}
