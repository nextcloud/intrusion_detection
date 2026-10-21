<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCP\Config\IUserConfig;
use OCP\IUserManager;
use OCP\Server;

/**
 * Real accounts with a first login of a chosen age, for the checks that only
 * count established accounts ({@see \OCA\IntrusionDetection\Login\EstablishedAccounts}).
 * The test calls deleteAccounts() in its tearDown().
 */
trait CreatesAccounts {
	/** @var list<string> */
	private array $accountUids = [];

	/**
	 * @param ?int $age seconds since the first login; null for an account that never logged in
	 * @return string the uid
	 */
	protected function account(string $prefix, ?int $age = 4 * 86400): string {
		$uid = $prefix . '-' . bin2hex(random_bytes(3));
		Server::get(IUserManager::class)->createUser($uid, 'A-long-test-password-' . $uid);
		$this->accountUids[] = $uid;
		if ($age !== null) {
			Server::get(IUserConfig::class)->setValueInt($uid, 'login', 'firstLogin', time() - $age);
		}
		return $uid;
	}

	/**
	 * @return list<string>
	 */
	protected function accounts(int $count, ?int $age = 4 * 86400): array {
		$uids = [];
		for ($i = 0; $i < $count; $i++) {
			$uids[] = $this->account('ids-person' . $i, $age);
		}
		return $uids;
	}

	protected function deleteAccounts(): void {
		foreach ($this->accountUids as $uid) {
			Server::get(IUserManager::class)->get($uid)?->delete();
		}
		$this->accountUids = [];
	}
}
