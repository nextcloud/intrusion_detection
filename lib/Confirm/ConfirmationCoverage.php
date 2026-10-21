<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

use OCA\IntrusionDetection\AdminChange\Approvers;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Authentication\TwoFactorAuth\IRegistry;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\Group\Backend\INamedBackend;
use OCP\ICacheFactory;
use OCP\IDBConnection;
use OCP\IGroupManager;
use OCP\IUser;
use OCP\IUserManager;

/**
 * Which accounts have no way to confirm a login: neither a second factor
 * nor an email address (concept sections 11.5, 16.2 and setup checks 9 and
 * 10). If a check asks them to confirm, the "no method" policies decide.
 *
 * Only active accounts count: enabled ones that logged in at least once.
 * Counting never loads accounts: it is one query over core's preferences
 * and second-factor tables, through their indexes. The counts are stored
 * (setting `coverage_users`): an hourly job and an explicit refresh count
 * again, the pages and setup checks only read them. Lists are read a page
 * at a time. Administrators (at most {@see Approvers::MAX}) are checked one
 * by one and cached for CACHE_TTL.
 */
class ConfirmationCoverage {
	public const CACHE_TTL = 3600;
	/** Backup codes alone are not a second factor */
	public const BACKUP_CODES = 'backup_codes';
	/** A user list returns at most this many accounts */
	public const MAX_LIST = 200;
	/** Share of active accounts above which setup check 9 warns */
	public const WARNING_SHARE = 0.10;
	/** The name core's own group backend gives itself */
	private const DATABASE_GROUP_BACKEND = 'Database';

	public function __construct(
		private readonly IDBConnection $db,
		private readonly IUserManager $userManager,
		private readonly IGroupManager $groupManager,
		private readonly Approvers $approvers,
		private readonly IRegistry $twoFactor,
		private readonly ICacheFactory $cacheFactory,
		private readonly Settings $settings,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * The stored counts; counted now when none were stored, or when they are
	 * older than an hour because the background job did not run.
	 *
	 * @return array{withoutMethod: int, active: int, countedAt: int}
	 */
	public function users(): array {
		$stored = $this->settings->getJson(GlobalSettings::COVERAGE_USERS);
		if (is_int($stored['withoutMethod'] ?? null) && is_int($stored['active'] ?? null) && is_int($stored['countedAt'] ?? null)
			&& $this->timeFactory->getTime() - $stored['countedAt'] <= self::CACHE_TTL) {
			return ['withoutMethod' => $stored['withoutMethod'], 'active' => $stored['active'], 'countedAt' => $stored['countedAt']];
		}
		return $this->recount();
	}

	/**
	 * Count the accounts again and store the counts.
	 *
	 * @return array{withoutMethod: int, active: int, countedAt: int}
	 */
	public function recount(): array {
		$counts = ['withoutMethod' => $this->count(true), 'active' => $this->count(false), 'countedAt' => $this->timeFactory->getTime()];
		$this->settings->setGlobal(GlobalSettings::COVERAGE_USERS, $counts);
		return $counts;
	}

	/**
	 * The enabled members of the admin group, and which of them have no
	 * email address or no second factor.
	 *
	 * @return array{total: int, withoutEmail: list<string>, withoutSecondFactor: list<string>, withNeither: list<string>}
	 */
	public function admins(): array {
		$cache = $this->cacheFactory->createDistributed('intrusion_detection_coverage');
		$cached = $cache->get('admins');
		if (is_array($cached) && is_int($cached['total'] ?? null)) {
			/** @var array{total: int, withoutEmail: list<string>, withoutSecondFactor: list<string>, withNeither: list<string>} $cached */
			return $cached;
		}
		$admins = $this->approvers->all();
		$withoutEmail = [];
		$withoutSecondFactor = [];
		$withNeither = [];
		foreach ($admins as $admin) {
			$email = (string)$admin->getEMailAddress() !== '';
			$secondFactor = $this->hasSecondFactor($admin);
			if (!$email) {
				$withoutEmail[] = $admin->getUID();
			}
			if (!$secondFactor) {
				$withoutSecondFactor[] = $admin->getUID();
			}
			if (!$email && !$secondFactor) {
				$withNeither[] = $admin->getUID();
			}
		}
		$result = ['total' => count($admins), 'withoutEmail' => $withoutEmail, 'withoutSecondFactor' => $withoutSecondFactor, 'withNeither' => $withNeither];
		$cache->set('admins', $result, self::CACHE_TTL);
		return $result;
	}

	/**
	 * Count again now, for example after the admin page asked for fresh numbers.
	 */
	public function refresh(): void {
		$this->cacheFactory->createDistributed('intrusion_detection_coverage')->remove('admins');
		$this->recount();
	}

	/**
	 * One page of the active accounts without a way to confirm, by uid.
	 * A page costs a few queries whatever its size: the display names come
	 * with the page, the groups and last logins are read for the whole page.
	 *
	 * @param bool $adminsOnly only members of the admin group
	 * @param ?string $after the uid the previous page ended with; the next page starts after it, without counting the rows before it as `$offset` does
	 * @return list<array{uid: string, displayName: string, lastLogin: int, groups: list<string>, admin: bool}>
	 */
	public function list(int $limit, int $offset = 0, bool $adminsOnly = false, ?string $after = null): array {
		$limit = max(1, min(self::MAX_LIST, $limit));
		if ($adminsOnly) {
			$uids = $this->admins()['withNeither'];
			sort($uids, SORT_STRING);
			if ($after !== null) {
				$uids = array_values(array_filter($uids, static fn (string $uid): bool => strcmp($uid, $after) > 0));
			}
			$uids = array_slice($uids, $after === null ? max(0, $offset) : 0, $limit);
			$lastLogins = $this->lastLogins($uids);
			$rows = array_map(static fn (string $uid): array => ['uid' => $uid, 'lastLogin' => $lastLogins[$uid] ?? 0, 'displayName' => null], $uids);
		} else {
			$qb = $this->db->getQueryBuilder();
			$qb->select('p.userid', 'p.configvalue', 'u.uid', 'u.displayname');
			$this->activeAccounts($qb, true);
			// Display names of the database's own accounts; other backends are asked below.
			$qb->leftJoin('p', 'users', 'u', $qb->expr()->eq('u.uid', 'p.userid'))
				->orderBy('p.userid')
				->setMaxResults($limit);
			if ($after !== null) {
				$qb->andWhere($qb->expr()->gt('p.userid', $qb->createNamedParameter($after)));
			} else {
				$qb->setFirstResult(max(0, $offset));
			}
			$result = $qb->executeQuery();
			$rows = [];
			while ($row = $result->fetch()) {
				$uid = (string)$row['userid'];
				$displayName = $row['uid'] === null ? null : trim((string)$row['displayname']);
				$rows[] = ['uid' => $uid, 'lastLogin' => (int)$row['configvalue'], 'displayName' => $displayName === null ? null : ($displayName === '' ? $uid : $displayName)];
			}
			$result->closeCursor();
		}
		$groups = $this->groupsOf(array_column($rows, 'uid'));
		$list = [];
		foreach ($rows as $row) {
			$displayName = $row['displayName'] ?? $this->userManager->getDisplayName($row['uid']);
			if ($displayName === null) {
				// Gone from its user backend.
				continue;
			}
			$userGroups = $groups[$row['uid']] ?? [];
			$list[] = [
				'uid' => $row['uid'],
				'displayName' => $displayName,
				'lastLogin' => $row['lastLogin'],
				'groups' => $userGroups,
				'admin' => in_array(Approvers::ADMIN_GROUP, $userGroups, true),
			];
		}
		return $list;
	}

	public function hasSecondFactor(IUser $user): bool {
		foreach ($this->twoFactor->getProviderStates($user) as $provider => $enabled) {
			if ($enabled && $provider !== self::BACKUP_CODES) {
				return true;
			}
		}
		return false;
	}

	private function count(bool $withoutMethod): int {
		$qb = $this->db->getQueryBuilder();
		$qb->select($qb->func()->count('*'));
		$this->activeAccounts($qb, $withoutMethod);
		$result = $qb->executeQuery();
		$count = (int)$result->fetchOne();
		$result->closeCursor();
		return $count;
	}

	/**
	 * Enabled accounts that logged in at least once (core's login/lastLogin
	 * value, through the preferences' (appid, configkey) index), and with
	 * $withoutMethod only those with neither an email address nor a second
	 * factor, each tested by primary key or index.
	 *
	 * Disabled accounts are left out with a left join on their primary key:
	 * PostgreSQL misestimates the equivalent NOT EXISTS on configvalue and
	 * took seconds for it with many accounts.
	 */
	private function activeAccounts(IQueryBuilder $qb, bool $withoutMethod): void {
		$qb->from('preferences', 'p')
			->leftJoin('p', 'preferences', 'd', $qb->expr()->andX(
				$qb->expr()->eq('d.userid', 'p.userid'),
				$qb->expr()->eq('d.appid', $qb->createNamedParameter('core')),
				$qb->expr()->eq('d.configkey', $qb->createNamedParameter('enabled')),
				$qb->expr()->eq('d.configvalue', $qb->createNamedParameter('false'), IQueryBuilder::PARAM_STR),
			))
			->where($qb->expr()->eq('p.appid', $qb->createNamedParameter('login')))
			->andWhere($qb->expr()->eq('p.configkey', $qb->createNamedParameter('lastLogin')))
			->andWhere($qb->expr()->isNull('d.userid'));
		if (!$withoutMethod) {
			return;
		}

		// An empty address deletes the value, so any row is an address.
		$email = $this->db->getQueryBuilder();
		$email->select('e.userid')
			->from('preferences', 'e')
			->where($email->expr()->eq('e.userid', 'p.userid'))
			->andWhere($email->expr()->eq('e.appid', $qb->createNamedParameter('settings')))
			->andWhere($email->expr()->in('e.configkey', $qb->createNamedParameter(['email', 'primary_email'], IQueryBuilder::PARAM_STR_ARRAY)));
		$qb->andWhere($qb->createFunction('NOT EXISTS (' . $email->getSQL() . ')'));

		$secondFactor = $this->db->getQueryBuilder();
		$secondFactor->select('t.uid')
			->from('twofactor_providers', 't')
			->where($secondFactor->expr()->eq('t.uid', 'p.userid'))
			->andWhere($secondFactor->expr()->eq('t.enabled', $qb->createNamedParameter(1, IQueryBuilder::PARAM_INT)))
			->andWhere($secondFactor->expr()->neq('t.provider_id', $qb->createNamedParameter(self::BACKUP_CODES)));
		$qb->andWhere($qb->createFunction('NOT EXISTS (' . $secondFactor->getSQL() . ')'));
	}

	/**
	 * @param list<string> $uids
	 * @return array<string, int> core's last login per uid, for those that have one
	 */
	private function lastLogins(array $uids): array {
		if ($uids === []) {
			return [];
		}
		$qb = $this->db->getQueryBuilder();
		$qb->select('userid', 'configvalue')
			->from('preferences')
			->where($qb->expr()->in('userid', $qb->createNamedParameter($uids, IQueryBuilder::PARAM_STR_ARRAY)))
			->andWhere($qb->expr()->eq('appid', $qb->createNamedParameter('login')))
			->andWhere($qb->expr()->eq('configkey', $qb->createNamedParameter('lastLogin')));
		$result = $qb->executeQuery();
		$lastLogins = [];
		while ($row = $result->fetch()) {
			$lastLogins[(string)$row['userid']] = (int)$row['configvalue'];
		}
		$result->closeCursor();
		return $lastLogins;
	}

	/**
	 * The groups of several accounts, sorted: the database's own groups in
	 * one query, the groups of other group backends (e.g. LDAP) per account.
	 *
	 * @param list<string> $uids
	 * @return array<string, list<string>>
	 */
	private function groupsOf(array $uids): array {
		if ($uids === []) {
			return [];
		}
		$groups = array_fill_keys($uids, []);
		$database = false;
		foreach ($this->groupManager->getBackends() as $backend) {
			if ($backend instanceof INamedBackend && $backend->getBackendName() === self::DATABASE_GROUP_BACKEND) {
				$database = true;
				continue;
			}
			foreach ($uids as $uid) {
				foreach ($backend->getUserGroups($uid) as $gid) {
					$groups[$uid][] = (string)$gid;
				}
			}
		}
		if ($database) {
			$qb = $this->db->getQueryBuilder();
			$qb->select('uid', 'gid')
				->from('group_user')
				->where($qb->expr()->in('uid', $qb->createNamedParameter($uids, IQueryBuilder::PARAM_STR_ARRAY)));
			$result = $qb->executeQuery();
			while ($row = $result->fetch()) {
				$groups[(string)$row['uid']][] = (string)$row['gid'];
			}
			$result->closeCursor();
		}
		foreach ($groups as $uid => $gids) {
			$gids = array_values(array_unique($gids));
			sort($gids);
			$groups[$uid] = $gids;
		}
		return $groups;
	}
}
