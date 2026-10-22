<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Login;

use OC\Memcache\ArrayCache;
use OCA\IntrusionDetection\Login\EstablishedAccounts;
use OCA\IntrusionDetection\Tests\Unit\Cache\FixedCaches;
use OCP\Config\IUserConfig;
use OCP\Config\ValueType;
use OCP\IGroupManager;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;

class EstablishedAccountsTest extends TestCase {
	private const NOW = 1792490400;

	private IUserConfig&MockObject $userConfig;
	private IGroupManager&MockObject $groups;
	/** @var array<string, int> first login per uid */
	private array $firstLogins = [];
	private int $lookups = 0;

	protected function setUp(): void {
		parent::setUp();
		$this->userConfig = $this->createMock(IUserConfig::class);
		$this->userConfig->method('getValuesByUsers')->willReturnCallback(function (string $app, string $key, ?ValueType $type, array $uids): array {
			$this->assertSame(['login', 'firstLogin', ValueType::INT], [$app, $key, $type]);
			$this->lookups++;
			return array_intersect_key($this->firstLogins, array_flip($uids));
		});
		$this->groups = $this->createMock(IGroupManager::class);
		$this->groups->method('isAdmin')->willReturnCallback(static fn (string $uid): bool => $uid === 'admin');
	}

	/**
	 * @return array<string, array{int, bool}>
	 */
	public static function ages(): array {
		return [
			'first login 4 days ago' => [self::NOW - 4 * 86400, true],
			'exactly 3 days ago' => [self::NOW - EstablishedAccounts::MIN_AGE, true],
			'2 days ago' => [self::NOW - 2 * 86400, false],
			'today' => [self::NOW - 600, false],
			'never logged in' => [0, false],
			'before Nextcloud recorded first logins' => [-1, true],
		];
	}

	#[DataProvider('ages')]
	public function testOnlyAccountsAtLeastThreeDaysOldCount(int $firstLogin, bool $counts): void {
		$this->firstLogins['alice'] = $firstLogin;
		$this->assertSame($counts, $this->accounts(null)->counts('alice', self::NOW));
	}

	public function testAnAdministratorAlwaysCounts(): void {
		$this->firstLogins['admin'] = self::NOW - 60;
		$this->assertTrue($this->accounts(null)->counts('admin', self::NOW));
	}

	public function testAnUnknownAccountDoesNotCount(): void {
		$this->assertFalse($this->accounts(null)->counts('ghost', self::NOW));
	}

	public function testFiveNewAccountsCountNone(): void {
		foreach (['a', 'b', 'c', 'd', 'e'] as $uid) {
			$this->firstLogins[$uid] = self::NOW - 3600;
		}
		$this->assertSame(0, $this->accounts(null)->count(['a', 'b', 'c', 'd', 'e'], self::NOW));
	}

	public function testTheAccountsOfAnAddressAreReadWithOneLookup(): void {
		foreach (['a', 'b', 'c', 'd', 'e'] as $uid) {
			$this->firstLogins[$uid] = self::NOW - 10 * 86400;
		}
		$this->assertSame(5, $this->accounts(null)->count(['a', 'b', 'c', 'd', 'e'], self::NOW));
		$this->assertSame(1, $this->lookups);
	}

	public function testTheFirstLoginIsRememberedAndTheAgeComputedEachTime(): void {
		$this->firstLogins['alice'] = self::NOW - 2 * 86400;
		$cache = new ArrayCache('ids-test-accounts');
		$this->assertFalse($this->accounts($cache)->counts('alice', self::NOW));
		$this->assertFalse($this->accounts($cache)->counts('alice', self::NOW + 3600), 'Another request on the same web server');
		$this->assertTrue($this->accounts($cache)->counts('alice', self::NOW + 86400), 'Old enough a day later, from the remembered first login');
		$this->assertSame(1, $this->lookups);
	}

	private function accounts(?ArrayCache $cache): EstablishedAccounts {
		return new EstablishedAccounts($this->userConfig, $this->groups, new FixedCaches(null, $cache));
	}
}
