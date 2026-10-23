<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Response;

use OCA\IntrusionDetection\Db\KeyMatch;

/**
 * The logins that vouch for an address when a block of it is decided
 * ({@see BanExemptions}): the login history answers.
 */
interface IAcceptedLogins {
	/**
	 * The different accounts with logins from an address (`ip`) or networks
	 * (`net_key`) since a time that were not refused or left unconfirmed, at
	 * most `$limit`.
	 *
	 * @param 'ip'|'net_key' $column
	 * @return list<string>
	 */
	public function acceptedUidsFrom(string $column, KeyMatch $keys, int $since, int $limit): array;

	/**
	 * Whether the account confirmed a login (a second factor, an email code,
	 * admin approval or a remembered device) from an address (`ip`) or
	 * networks (`net_key`) since a time.
	 *
	 * @param 'ip'|'net_key' $column
	 */
	public function hasConfirmedLogin(string $uid, string $column, KeyMatch $keys, int $since): bool;
}
