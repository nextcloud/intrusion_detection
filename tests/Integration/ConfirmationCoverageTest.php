<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\Memcache\ArrayCache;
use OCA\IntrusionDetection\AdminChange\Approvers;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\BackgroundJob\StatusRefreshJob;
use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Config\UserKeys;
use OCA\IntrusionDetection\Confirm\AccountMethods;
use OCA\IntrusionDetection\Confirm\ConfirmationCoverage;
use OCA\IntrusionDetection\Confirm\SecondFactors;
use OCA\IntrusionDetection\Confirm\UntrustedSecondFactors;
use OCA\IntrusionDetection\Notification\AdminLinks;
use OCA\IntrusionDetection\Notification\MailReach;
use OCA\IntrusionDetection\SetupCheck\Finding;
use OCA\IntrusionDetection\SetupCheck\UsersWithoutConfirmationCheck;
use OCA\IntrusionDetection\StaleCredential\StaleCredentialSweep;
use OCA\IntrusionDetection\State\AppState;
use OCA\IntrusionDetection\Tests\Unit\Cache\FixedCaches;
use OCA\IntrusionDetection\Traps\TrapNameCollisions;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Config\IUserConfig;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\IConfig;
use OCP\IGroupManager;
use OCP\IUser;
use OCP\IUserManager;
use OCP\L10N\IFactory;
use OCP\Mail\IEmailValidator;
use OCP\Server;
use PHPUnit\Framework\Attributes\DataProvider;
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

	/**
	 * The query counts and lists exactly the accounts a login finds without
	 * a method of their own ({@see AccountMethods::any()}).
	 */
	#[DataProvider('mailModes')]
	public function testTheQueryAgreesWithWhatALoginAccepts(bool $sendsMail): void {
		$config = $this->createMock(IConfig::class);
		$config->method('getSystemValueString')->willReturnCallback(static fn (string $key, string $default): string => $key === 'mail_smtpmode' ? ($sendsMail ? 'smtp' : 'null') : $default);
		$reach = new MailReach(Server::get(IEmailValidator::class), $config);
		$coverage = $this->coverage($reach);
		$before = $coverage->recount()['withoutMethod'];
		$now = time();
		$this->account('a-none');
		$this->account('a-email', email: true);
		$this->account('a-totp', secondFactor: 'totp');
		$this->account('a-backup', secondFactor: 'backup_codes');
		$this->account('a-untrusted', secondFactor: 'totp', marks: ['totp' => $now - 60]);
		$this->account('a-untrusted-email', email: true, secondFactor: 'totp', marks: ['totp' => $now - 60]);
		$this->account('a-still-untrusted', secondFactor: 'totp', marks: ['totp' => ['at' => $now - 60, 'until' => $now + 3600]]);
		$this->account('a-mark-ended', secondFactor: 'totp', marks: ['totp' => ['at' => $now - 7200, 'until' => $now - 3600]]);
		$this->account('a-one-of-two', secondFactor: 'totp', marks: ['webauthn' => $now - 60]);
		$this->addSecondFactor(self::PREFIX . 'a-one-of-two', 'webauthn');
		$this->account('a-other-mark', secondFactor: 'totp', marks: ['webauthn' => $now - 60]);

		$methods = new AccountMethods($reach, Server::get(SecondFactors::class));
		$expected = [];
		foreach ($this->users as $uid) {
			$user = Server::get(IUserManager::class)->get($uid);
			$this->assertInstanceOf(IUser::class, $user);
			if (!$methods->any($user)) {
				$expected[] = $uid;
			}
		}
		sort($expected);
		$listed = array_values(array_filter(array_column($coverage->list(200, 0, false, self::PREFIX . 'a-'), 'uid'), static fn (string $uid): bool => str_starts_with($uid, self::PREFIX . 'a-')));

		$this->assertSame($expected, $listed);
		$this->assertSame($before + count($expected), $coverage->recount()['withoutMethod']);
		$this->assertContains(self::PREFIX . 'a-untrusted', $listed, 'an untrusted second factor confirms nothing');
		$this->assertNotContains(self::PREFIX . 'a-mark-ended', $listed, 'a mark that ended counts no more');
		$this->assertSame(!$sendsMail, in_array(self::PREFIX . 'a-email', $listed, true), 'an address is a method only while the server sends mail');
	}

	/**
	 * @return array<string, array{bool}>
	 */
	public static function mailModes(): array {
		return ['the server sends mail' => [true], 'the server sends no mail' => [false]];
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
		$coverage = new ConfirmationCoverage($this->db, $userManager, $this->createMock(IGroupManager::class), $this->createMock(Approvers::class), Server::get(AccountMethods::class), Server::get(SecondFactors::class), Server::get(MailReach::class), $this->cacheFactory(), Server::get(ITimeFactory::class), Server::get(AppState::class));

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

	private function coverage(?MailReach $reach = null): ConfirmationCoverage {
		$reach ??= Server::get(MailReach::class);
		$secondFactors = Server::get(SecondFactors::class);
		return new ConfirmationCoverage(
			$this->db,
			Server::get(IUserManager::class),
			Server::get(IGroupManager::class),
			Server::get(Approvers::class),
			new AccountMethods($reach, $secondFactors),
			$secondFactors,
			$reach,
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

	/**
	 * @param array<string, int|array{at: int, until: int}> $marks untrusted second factors ({@see UntrustedSecondFactors})
	 */
	private function account(string $name, bool $email = false, ?string $secondFactor = null, bool $disabled = false, bool $loggedIn = true, array $marks = []): string {
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
			$this->addSecondFactor($uid, $secondFactor);
		}
		if ($marks !== []) {
			Server::get(IUserConfig::class)->setValueArray($uid, Application::APP_ID, UserKeys::UNTRUSTED_SECOND_FACTORS, $marks);
		}
		if ($disabled) {
			$user->setEnabled(false);
		}
		if ($loggedIn) {
			$this->preference($uid, 'login', 'lastLogin', '1760000000');
		}
		return $uid;
	}

	private function addSecondFactor(string $uid, string $providerId): void {
		$this->db->insertIfNotExist('*PREFIX*twofactor_providers', ['provider_id' => $providerId, 'uid' => $uid, 'enabled' => 1], ['provider_id', 'uid']);
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
