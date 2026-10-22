<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\Memcache\ArrayCache;
use OCA\IntrusionDetection\AdminChange\Approvers;
use OCA\IntrusionDetection\BackgroundJob\StatusRefreshJob;
use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Confirm\ConfirmationCoverage;
use OCA\IntrusionDetection\Notification\AdminLinks;
use OCA\IntrusionDetection\SetupCheck\Finding;
use OCA\IntrusionDetection\SetupCheck\UsersWithoutConfirmationCheck;
use OCA\IntrusionDetection\StaleCredential\StaleCredentialSweep;
use OCA\IntrusionDetection\State\AppState;
use OCA\IntrusionDetection\Tests\Unit\Cache\FixedCaches;
use OCA\IntrusionDetection\Traps\TrapNameCollisions;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Authentication\TwoFactorAuth\IRegistry;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IGroupManager;
use OCP\IUser;
use OCP\IUserManager;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;

/**
 * Counting the accounts that cannot confirm a login (setup checks 9 and 10,
 * the Confirmation tab): only enabled accounts that logged in, neither an
 * email address nor a second factor, counted with queries rather than by
 * loading accounts, and cached.
 */
#[Group('DB')]
class ConfirmationCoverageTest extends IntegrationTestCase {
	private const PREFIX = 'ids-cov-';

	private ArrayCache $cache;
	/** @var list<string> */
	private array $users = [];

	protected function setUp(): void {
		parent::setUp();
		$this->cache = new ArrayCache();
		$this->removeFakeAccounts();
	}

	protected function tearDown(): void {
		foreach ($this->users as $uid) {
			Server::get(IUserManager::class)->get($uid)?->delete();
		}
		$this->removeFakeAccounts();
		parent::tearDown();
	}

	public function testOnlyActiveAccountsWithoutEmailOrSecondFactorCount(): void {
		$before = $this->coverage()->users();
		$none = $this->account('none');
		$this->account('email', email: true);
		$this->account('totp', secondFactor: 'totp');
		$this->account('backup', secondFactor: 'backup_codes');
		$this->account('disabled', disabled: true);
		$this->account('never', loggedIn: false);
		$this->forgetCounts();

		$counts = $this->coverage()->users();
		$this->assertSame($before['withoutMethod'] + 2, $counts['withoutMethod'], 'Nothing, or backup codes only');
		$this->assertSame($before['active'] + 4, $counts['active'], 'Disabled and never logged in do not count');

		$listed = array_column($this->coverage()->list(200), 'uid');
		$this->assertContains($none, $listed);
		$this->assertContains(self::PREFIX . 'backup', $listed);
		$this->assertNotContains(self::PREFIX . 'email', $listed);
		$row = array_values(array_filter($this->coverage()->list(200), static fn (array $r): bool => $r['uid'] === $none))[0];
		$this->assertSame(1_760_000_000, $row['lastLogin']);
		$this->assertSame(['staff'], $row['groups']);
		$this->assertFalse($row['admin']);
	}

	public function testAPageCostsTheSameFewQueriesWhateverItsSizeAndTheNextOneStartsAfterIt(): void {
		$uids = [];
		for ($i = 1; $i <= 6; $i++) {
			$uids[] = $this->account('page' . $i);
		}
		Server::get(IUserManager::class)->get($uids[1])?->setDisplayName('Second Page');
		$coverage = $this->coverage();
		$mine = static fn (array $rows): array => array_values(array_filter(array_column($rows, 'uid'), static fn (string $uid): bool => str_starts_with($uid, self::PREFIX . 'page')));

		$queries = $this->db->getInner()->getStats()['executed'];
		$first = $coverage->list(3, 0, false, self::PREFIX . 'page');
		$small = $this->db->getInner()->getStats()['executed'] - $queries;
		$this->assertSame(array_slice($uids, 0, 3), $mine($first));
		$this->assertSame('Second Page', $first[1]['displayName']);
		$this->assertSame(['staff'], $first[0]['groups']);

		$queries = $this->db->getInner()->getStats()['executed'];
		$all = $coverage->list(6, 0, false, self::PREFIX . 'page');
		$this->assertSame($uids, $mine($all));
		$this->assertSame($small, $this->db->getInner()->getStats()['executed'] - $queries, 'no query per account');
		$this->assertLessThanOrEqual(3, $small, 'the page and the groups');

		$next = $coverage->list(3, 0, false, $uids[2]);
		$this->assertSame(array_slice($uids, 3, 3), $mine($next), 'starts after the last account of the page before');
	}

	public function testTheCountsAreStoredUntilTheJobOrARefreshCountsAgain(): void {
		$coverage = $this->coverage();
		$first = $coverage->users();
		$this->account('cached');

		$queries = $this->db->getInner()->getStats()['executed'];
		$this->assertSame($first, $this->coverage()->users(), 'Stored, also for a new request');
		$this->assertSame(1, $this->db->getInner()->getStats()['executed'] - $queries, 'Reading the counts costs one read of the stored counts, no count');

		$coverage->refresh();
		$this->assertSame($first['withoutMethod'] + 1, $coverage->users()['withoutMethod']);

		$this->account('job');
		self::invokePrivate(new StatusRefreshJob(Server::get(ITimeFactory::class), $coverage, Server::get(TrapNameCollisions::class), Server::get(StaleCredentialSweep::class), Server::get(LoggerInterface::class)), 'run', [null]);
		$this->assertSame($first['withoutMethod'] + 2, $coverage->users()['withoutMethod']);
	}

	public function testCountsOlderThanAnHourAreCountedAgain(): void {
		$this->coverage()->users();
		$this->account('late');
		$stored = Server::get(AppState::class)->getJson(ConfirmationCoverage::USERS_STATE);
		$stale = ['withoutMethod' => 0, 'active' => 0, 'countedAt' => time() - ConfirmationCoverage::CACHE_TTL - 60];
		Server::get(AppState::class)->setJson(ConfirmationCoverage::USERS_STATE, $stale);

		$counts = $this->coverage()->users();

		$this->assertGreaterThan(0, $counts['withoutMethod'], 'counted again without the job');
		$this->assertGreaterThanOrEqual($stored['countedAt'], $counts['countedAt']);
	}

	public function testCountingTenThousandAccountsLoadsNoAccount(): void {
		$before = $this->coverage()->users();
		$this->forgetCounts();
		$this->fakeAccounts(10_000);
		$userManager = $this->createMock(IUserManager::class);
		$userManager->expects($this->never())->method($this->anything());
		$coverage = new ConfirmationCoverage($this->db, $userManager, $this->createMock(IGroupManager::class), $this->createMock(Approvers::class), $this->createMock(IRegistry::class), $this->cacheFactory(), Server::get(ITimeFactory::class), Server::get(AppState::class));

		$start = hrtime(true);
		$counts = $coverage->users();
		$elapsed = (hrtime(true) - $start) / 1e9;
		// Every fourth has an email address, every fifth a second factor, every twentieth both.
		$this->assertSame($before['withoutMethod'] + 6_000, $counts['withoutMethod']);
		$this->assertSame($before['active'] + 10_000, $counts['active']);
		$this->assertLessThan(2.0, $elapsed, 'Two indexed queries, not a loop over accounts');

		$l = Server::get(IFactory::class)->get('intrusion_detection', 'en');
		$check = new UsersWithoutConfirmationCheck($l, $this->createMock(AdminLinks::class), $coverage);
		$this->assertSame(Finding::LEVEL_WARNING, $check->finding($l)?->level, 'Far more than a tenth');
	}

	private function coverage(): ConfirmationCoverage {
		return new ConfirmationCoverage(
			$this->db,
			Server::get(IUserManager::class),
			Server::get(IGroupManager::class),
			Server::get(Approvers::class),
			Server::get(IRegistry::class),
			$this->cacheFactory(),
			Server::get(ITimeFactory::class),
			Server::get(AppState::class),
		);
	}

	private function forgetCounts(): void {
		Server::get(AppState::class)->delete(ConfirmationCoverage::USERS_STATE);
	}

	private function cacheFactory(): Caches {
		$factory = new FixedCaches($this->cache);
		return $factory;
	}

	private function account(string $name, bool $email = false, ?string $secondFactor = null, bool $disabled = false, bool $loggedIn = true): string {
		$uid = self::PREFIX . $name;
		$user = Server::get(IUserManager::class)->createUser($uid, 'A-long-test-password-' . $uid);
		$this->assertInstanceOf(IUser::class, $user);
		$this->users[] = $uid;
		$group = Server::get(IGroupManager::class)->get('staff') ?? Server::get(IGroupManager::class)->createGroup('staff');
		$group?->addUser($user);
		if ($email) {
			$user->setSystemEMailAddress($name . '@example.com');
		}
		if ($secondFactor !== null) {
			$this->db->insertIfNotExist('*PREFIX*twofactor_providers', ['provider_id' => $secondFactor, 'uid' => $uid, 'enabled' => 1], ['provider_id', 'uid']);
		}
		if ($disabled) {
			$user->setEnabled(false);
		}
		if ($loggedIn) {
			$this->preference($uid, 'login', 'lastLogin', '1760000000');
		}
		return $uid;
	}

	/**
	 * Accounts that only exist as rows, like accounts of a large directory.
	 */
	private function fakeAccounts(int $count): void {
		$this->db->beginTransaction();
		for ($i = 0; $i < $count; $i++) {
			$uid = self::PREFIX . 'fake-' . $i;
			$this->preference($uid, 'login', 'lastLogin', '1760000000');
			if ($i % 4 === 0) {
				$this->preference($uid, 'settings', 'email', $uid . '@example.com');
			}
			if ($i % 5 === 0) {
				$qb = $this->db->getQueryBuilder();
				$qb->insert('twofactor_providers')->values([
					'provider_id' => $qb->createNamedParameter('totp'),
					'uid' => $qb->createNamedParameter($uid),
					'enabled' => $qb->createNamedParameter(1, IQueryBuilder::PARAM_INT),
				])->executeStatement();
			}
		}
		$this->db->commit();
	}

	private function preference(string $uid, string $app, string $key, string $value): void {
		$qb = $this->db->getQueryBuilder();
		$qb->insert('preferences')->values([
			'userid' => $qb->createNamedParameter($uid),
			'appid' => $qb->createNamedParameter($app),
			'configkey' => $qb->createNamedParameter($key),
			'configvalue' => $qb->createNamedParameter($value),
		])->executeStatement();
	}

	private function removeFakeAccounts(): void {
		$qb = $this->db->getQueryBuilder();
		$qb->delete('preferences')->where($qb->expr()->like('userid', $qb->createNamedParameter(self::PREFIX . 'fake-%')))->executeStatement();
		$qb = $this->db->getQueryBuilder();
		$qb->delete('twofactor_providers')->where($qb->expr()->like('uid', $qb->createNamedParameter(self::PREFIX . '%')))->executeStatement();
	}
}
