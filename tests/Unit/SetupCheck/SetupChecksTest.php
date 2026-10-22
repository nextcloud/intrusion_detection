<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\SetupCheck;

use OC\Memcache\ArrayCache;
use OCA\IntrusionDetection\Address\AddressResolver;
use OCA\IntrusionDetection\Address\Verdict;
use OCA\IntrusionDetection\Check\Checks\ReservedName\ReservedName;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Config\Prerequisites;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Db\LoginMapper;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Learning\LearningService;
use OCA\IntrusionDetection\Login\EstablishedAccounts;
use OCA\IntrusionDetection\Notification\AdminLinks;
use OCA\IntrusionDetection\Response\ProxySuspect;
use OCA\IntrusionDetection\SetupCheck\BruteForceProtectionCheck;
use OCA\IntrusionDetection\SetupCheck\Finding;
use OCA\IntrusionDetection\SetupCheck\LearningModeCheck;
use OCA\IntrusionDetection\SetupCheck\MailCheck;
use OCA\IntrusionDetection\SetupCheck\MemoryCacheCheck;
use OCA\IntrusionDetection\SetupCheck\ReverseProxyCheck;
use OCA\IntrusionDetection\SetupCheck\SharedAddressCheck;
use OCA\IntrusionDetection\SetupCheck\TrapNameCollisionCheck;
use OCA\IntrusionDetection\State\AppState;
use OCA\IntrusionDetection\Tests\Unit\Cache\FixedCaches;
use OCA\IntrusionDetection\Traps\TrapNameCollisions;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IConfig;
use OCP\IL10N;
use OCP\IURLGenerator;
use OCP\L10N\IFactory;
use OCP\Server;
use OCP\SetupCheck\SetupResult;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;

class SetupChecksTest extends TestCase {
	private const NOW = 1_790_000_000;

	private IL10N $l;
	private AdminLinks&MockObject $links;
	private IURLGenerator&MockObject $urls;
	private ITimeFactory&MockObject $time;

	protected function setUp(): void {
		parent::setUp();
		$this->l = Server::get(IFactory::class)->get('intrusion_detection', 'en');
		$this->links = $this->createMock(AdminLinks::class);
		$this->links->method('adminPage')->willReturn('https://cloud.example.com/settings/admin/intrusion_detection');
		$this->urls = $this->createMock(IURLGenerator::class);
		$this->urls->method('linkToDocs')->willReturnCallback(static fn (string $key): string => 'https://docs.example.com/' . $key);
		$this->time = $this->createMock(ITimeFactory::class);
		$this->time->method('getTime')->willReturn(self::NOW);
	}

	/**
	 * @param list<array{ipKey: string, uid: string}> $logins
	 * @param list<string> $proxies
	 */
	private function proxyCheck(array $logins, array $proxies = []): ReverseProxyCheck {
		$mapper = $this->createMock(LoginMapper::class);
		$mapper->method('recent')->with(ProxySuspect::SAMPLE)->willReturn($logins);
		$config = $this->createMock(IConfig::class);
		$config->method('getSystemValue')->with('trusted_proxies', [])->willReturn($proxies);
		$accounts = $this->createMock(EstablishedAccounts::class);
		$accounts->method('count')->willReturnCallback(static fn (array $uids): int => count($uids));
		return new ReverseProxyCheck($this->l, $this->links, new ProxySuspect($mapper, $config, $accounts, $this->time), $this->urls);
	}

	public function testManyPeopleFromOnePrivateAddressPointToAProxy(): void {
		$logins = [];
		foreach (['alice', 'bob', 'carol', 'alice'] as $uid) {
			$logins[] = ['ipKey' => '10.0.0.2', 'uid' => $uid];
		}
		$logins[] = ['ipKey' => '203.0.113.7', 'uid' => 'dave'];
		$finding = $this->proxyCheck($logins)->finding($this->l);
		$this->assertNotNull($finding);
		$this->assertSame(Finding::LEVEL_WARNING, $finding->level);
		$this->assertSame('All visitors share one address – reverse proxy?', $finding->title);
		$this->assertStringContainsString('3 of the last 50 logins', $finding->text);
		$this->assertStringContainsString('10.0.0.2', $finding->text, 'the address is named in the text');
		$this->assertStringContainsString('trusted_proxies', $finding->fix);
		$this->assertSame('https://docs.example.com/admin-reverse-proxy', $finding->url);
		$this->assertSame(SetupResult::WARNING, $this->proxyCheck($logins)->run()->getSeverity());
	}

	public function testAProxyIsNotSuspectedWithoutCause(): void {
		$private = [['ipKey' => '10.0.0.2', 'uid' => 'a'], ['ipKey' => '10.0.0.2', 'uid' => 'b'], ['ipKey' => '10.0.0.2', 'uid' => 'c']];
		$this->assertNull($this->proxyCheck($private, ['10.0.0.2'])->finding($this->l), 'Trusted proxies are configured');
		$this->assertNull($this->proxyCheck(array_slice($private, 0, 2))->finding($this->l), 'Two people are no pattern');
		$public = array_map(static fn (array $r): array => ['ipKey' => '203.0.113.7', 'uid' => $r['uid']], $private);
		$this->assertNull($this->proxyCheck($public)->finding($this->l), 'A public address is an office, not a proxy');
		$this->assertSame(SetupResult::SUCCESS, $this->proxyCheck([])->run()->getSeverity());
	}

	public function testLoopbackCountsAsPrivate(): void {
		$logins = array_map(static fn (string $u): array => ['ipKey' => '127.0.0.1', 'uid' => $u], ['a', 'b', 'c']);
		$this->assertNotNull($this->proxyCheck($logins)->finding($this->l));
	}

	public function testBruteForceProtectionOff(): void {
		$config = $this->createMock(IConfig::class);
		$config->method('getSystemValueBool')->with('auth.bruteforce.protection.enabled', true)->willReturnOnConsecutiveCalls(true, false);
		$check = new BruteForceProtectionCheck($this->l, $this->links, $config, $this->urls);
		$this->assertNull($check->finding($this->l));
		$finding = $check->finding($this->l);
		$this->assertSame(Finding::LEVEL_INFO, $finding?->level);
	}

	public function testMailMissing(): void {
		$prerequisites = $this->createMock(Prerequisites::class);
		$prerequisites->method('hasMail')->willReturnOnConsecutiveCalls(true, false);
		$check = new MailCheck($this->l, $this->links, $prerequisites, $this->urls);
		$this->assertNull($check->finding($this->l));
		$this->assertSame(Finding::LEVEL_WARNING, $check->finding($this->l)?->level);
	}

	public function testWithoutAMemoryCacheTheCostIsMeasured(): void {
		$caches = FixedCaches::none();
		$resolver = $this->createMock(AddressResolver::class);
		$resolver->expects($this->exactly(3))->method('resolve')->willReturn(new Verdict(0, '', [], self::NOW + 300));
		$finding = (new MemoryCacheCheck($this->l, $this->links, $caches, $resolver, $this->urls))->finding($this->l);
		$this->assertSame(Finding::LEVEL_INFO, $finding?->level);
		$this->assertMatchesRegularExpression('/about \d+\.\d\d ms per request, measured just now/', (string)$finding?->text);
	}

	public function testAFailingMeasurementStillReportsTheMissingCache(): void {
		$caches = FixedCaches::none();
		$resolver = $this->createMock(AddressResolver::class);
		$resolver->method('resolve')->willThrowException(new \RuntimeException('db down'));
		$finding = (new MemoryCacheCheck($this->l, $this->links, $caches, $resolver, $this->urls))->finding($this->l);
		$this->assertStringNotContainsString('ms per request', (string)$finding?->text);
	}

	public function testAMemoryCacheIsFine(): void {
		$caches = new FixedCaches(new ArrayCache());
		$resolver = $this->createMock(AddressResolver::class);
		$resolver->expects($this->never())->method('resolve');
		$this->assertNull((new MemoryCacheCheck($this->l, $this->links, $caches, $resolver, $this->urls))->finding($this->l));
	}

	public function testTrapNamesThatBecameAccountsAreAnErrorWithALinkToTheTab(): void {
		$collisions = $this->createMock(TrapNameCollisions::class);
		$collisions->method('all')->willReturn(['admin', 'backup-svc', 'support']);
		$check = new TrapNameCollisionCheck($this->l, $this->links, $collisions, $this->reservedNameSettings(Mode::Protect, []));
		$finding = $check->finding($this->l);
		$this->assertSame(Finding::LEVEL_ERROR, $finding?->level);
		$this->assertStringContainsString('"admin", "backup-svc", "support" are reserved', (string)$finding?->text);
		$this->assertSame('#blocks-decoys', $finding?->url);

		$result = $check->run();
		$this->assertSame(SetupResult::ERROR, $result->getSeverity());
		$this->assertSame('https://cloud.example.com/settings/admin/intrusion_detection#blocks-decoys', $result->getLinkToDoc(), 'Core shows an absolute link');
	}

	public function testNoTrapNameCollision(): void {
		$check = new TrapNameCollisionCheck($this->l, $this->links, $this->createMock(TrapNameCollisions::class), $this->reservedNameSettings(Mode::Protect, ['administrator']));
		$this->assertNull($check->finding($this->l));
		$this->assertSame(SetupResult::SUCCESS, $check->run()->getSeverity());
	}

	public function testNoReservedNameIsATipWhileTheCheckRuns(): void {
		$check = new TrapNameCollisionCheck($this->l, $this->links, $this->createMock(TrapNameCollisions::class), $this->reservedNameSettings(Mode::Protect, []));
		$finding = $check->finding($this->l);
		$this->assertSame('reserved_names_empty', $finding?->id);
		$this->assertSame(Finding::LEVEL_INFO, $finding?->level);
		$this->assertStringContainsString('Add all', (string)$finding?->fix);
		$this->assertSame('#blocks-reserved', $finding?->url);
		$this->assertSame(SetupResult::INFO, $check->run()->getSeverity());

		$off = new TrapNameCollisionCheck($this->l, $this->links, $this->createMock(TrapNameCollisions::class), $this->reservedNameSettings(Mode::Off, []));
		$this->assertNull($off->finding($this->l), 'Nothing to say while the check is off');
	}

	/**
	 * @param list<string> $names
	 */
	private function reservedNameSettings(Mode $mode, array $names): CheckSettings&MockObject {
		$settings = $this->createMock(CheckSettings::class);
		$settings->method('modeState')->with(ReservedName::ID)->willReturn(new ModeState($mode, $mode));
		$settings->method('paramList')->with(ReservedName::ID, 'names')->willReturn($names);
		return $settings;
	}

	public function testSharedAddressDetectionsOfTheLastWeek(): void {
		$detections = $this->createMock(DetectionMapper::class);
		$detection = new Detection();
		$detection->setIp('192.0.2.10');
		$detections->method('count')->willReturnCallback(function (DetectionFilter $filter): int {
			$this->assertSame(['shared_address'], $filter->checkIds);
			$this->assertSame(self::NOW - 7 * 86400, $filter->since);
			return 2;
		});
		$detections->method('findList')->willReturn([$detection, $detection]);
		$finding = (new SharedAddressCheck($this->l, $this->links, $detections, $this->time, $this->urls))->finding($this->l);
		$this->assertSame(Finding::LEVEL_WARNING, $finding?->level);
		$this->assertStringContainsString('not blocked 2 times', (string)$finding?->text);
		$this->assertStringContainsString('192.0.2.10.', (string)$finding?->text);
	}

	public function testNoSharedAddress(): void {
		$detections = $this->createMock(DetectionMapper::class);
		$detections->method('count')->willReturn(0);
		$detections->expects($this->never())->method('findList');
		$this->assertNull((new SharedAddressCheck($this->l, $this->links, $detections, $this->time, $this->urls))->finding($this->l));
	}

	/**
	 * @param int $startedAt when learning started, 0 when unknown
	 */
	private function learningCheck(bool $active, int $startedAt, int $installedAt = 0): LearningModeCheck {
		$learning = $this->createMock(LearningService::class);
		$learning->method('isActive')->willReturn($active);
		$state = $this->createMock(AppState::class);
		$state->method('getInt')->willReturnMap([
			[LearningService::STARTED_STATE, $startedAt],
			[AppState::INSTALLED_AT, $installedAt],
		]);
		return new LearningModeCheck($this->l, $this->links, $learning, $this->time, $state);
	}

	public function testLearningForMoreThanTwoWeeks(): void {
		$finding = $this->learningCheck(true, self::NOW - 15 * 86400)->finding($this->l);
		$this->assertSame(Finding::LEVEL_INFO, $finding?->level);
		$this->assertStringContainsString('on for 15 days', (string)$finding?->text);
		$this->assertSame('#settings-learning', $finding?->url);
		$this->assertNotNull($this->learningCheck(true, 0, self::NOW - 20 * 86400)->finding($this->l), 'Falls back to the installation time');
	}

	public function testLearningSaysWhatStillBlocks(): void {
		$text = (string)$this->learningCheck(true, self::NOW - 15 * 86400)->finding($this->l)?->text;
		$this->assertStringContainsString('Learning mode has been on for 15 days. Checks set to Protect only record what they would block; earlier blocks', $text);
		$this->assertStringNotContainsString('no attacker', $text);
	}

	public function testNormalLearningIsFine(): void {
		$this->assertNull($this->learningCheck(true, self::NOW - 13 * 86400)->finding($this->l));
		$this->assertNull($this->learningCheck(false, self::NOW - 30 * 86400)->finding($this->l));
		$this->assertNull($this->learningCheck(true, 0, 0)->finding($this->l), 'Unknown start');
	}
}
