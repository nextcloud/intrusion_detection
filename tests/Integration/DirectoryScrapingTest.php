<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\DB\ConnectionAdapter;
use OC\Memcache\ArrayCache;
use OCA\IntrusionDetection\Address\Verdict;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\Checks\DirectoryScraping;
use OCA\IntrusionDetection\Check\Checks\DirectoryScrapingDetector;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Config\Prerequisites;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Definition\InvalidParamException;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\Requirement;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Detection\DetectionService;
use OCA\IntrusionDetection\Event\TypedEvents;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Guard\RequestContext;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\ServerAddresses;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCA\IntrusionDetection\Sensitive\DirectoryRoutes;
use OCA\IntrusionDetection\SessionState\CurrentSession;
use OCA\IntrusionDetection\SessionState\RequestTarget;
use OCA\IntrusionDetection\SessionState\Rules\DirectoryScrapingRule;
use OCA\IntrusionDetection\SessionState\SessionBlock;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCA\IntrusionDetection\Tests\Unit\Cache\FixedCaches;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IAppConfig;
use OCP\IConfig;
use OCP\IDBConnection;
use OCP\IRequest;
use OCP\ISession;
use OCP\IUser;
use OCP\IUserSession;
use OCP\L10N\IFactory;
use OCP\Security\Bruteforce\IThrottler;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * Directory scraping (concept section 10.16): counting in the memory cache,
 * one increment on matching requests and nothing on others, the limits,
 * the 429, Observe, and no counting at all without a memory cache.
 */
#[Group('DB')]
class DirectoryScrapingTest extends IntegrationTestCase {
	/** The start of a 10-minute bucket */
	private const NOW = 1792490400;

	private OperationCountingCache $cache;
	private Settings $settings;
	private int $now = self::NOW;
	private string $route = 'ocs.core.autocomplete.get';
	private ?string $providerId = null;
	/** @var list<string> services the rule asked the container for */
	private array $built = [];

	protected function setUp(): void {
		parent::setUp();
		$this->cache = new OperationCountingCache();
		$this->settings = $this->settingsWith(true);
		$this->settings->setParam(DirectoryScraping::ID, 'limit_search', 10);
	}

	public function testOtherRequestsCostNothing(): void {
		$queries = $this->queries();
		foreach (['files.view.index', 'core.avatar.postavatar', 'ocs.core.unifiedsearch.search'] as $route) {
			$this->route = $route;
			$this->providerId = 'files';
			$this->assertNull($this->rule()->check($this->state(), $this->appTarget()));
		}
		$this->assertNull($this->rule()->check($this->state(), RequestTarget::dav('PROPFIND', '/remote.php/dav/files/alice/')));
		$this->assertSame([], $this->built, 'The counter is not even built');
		$this->assertSame(0, $this->cache->operations);
		$this->assertSame(0, $this->queries() - $queries, 'No database query');
	}

	public function testAMatchingRequestCostsOneCacheIncrementAndNoQuery(): void {
		$this->rule()->check($this->state(), $this->appTarget());
		$this->assertSame(['inc' => 1, 'set' => 1], $this->cache->byType, 'The first request of a bucket also sets the lifetime');
		$queries = $this->queries();
		$this->cache->reset();
		for ($i = 0; $i < 5; $i++) {
			$this->assertNull($this->rule()->check($this->state(), $this->appTarget()));
		}
		$this->assertSame(['inc' => 5], $this->cache->byType, 'One increment per request');
		$this->assertSame(0, $this->queries() - $queries, 'No database query');
	}

	public function testAboveTheLimitTheAccountGets429UntilTheBucketEnds(): void {
		$this->now = self::NOW + 360;
		for ($i = 1; $i <= 10; $i++) {
			$this->assertNull($this->rule()->check($this->state(), $this->appTarget()), 'Request ' . $i . ' is within the limit');
		}
		$this->assertSame([], $this->detections());

		$block = $this->rule()->check($this->state(), $this->appTarget());
		$this->assertInstanceOf(SessionBlock::class, $block);
		$this->assertTrue($block->isRateLimit());
		$this->assertSame(240, $block->retryAfter, 'Until the 10-minute bucket ends');

		$detections = $this->detections();
		$this->assertCount(1, $detections);
		$detection = $detections[0];
		$this->assertTrue($detection->isEnforced());
		$this->assertSame('alice', $detection->getUid());
		$this->assertSame('203.0.113.9', $detection->getIp());
		$facts = $detection->getExplanationData()['facts'];
		$this->assertSame(DirectoryRoutes::GROUP_SEARCH, $facts['group']);
		$this->assertSame(11, $facts['count']);
		$this->assertSame(10, $facts['limit']);
		$this->assertSame(['rate_limit', 'notify_admin'], array_column($detection->getActionList(), 'type'));

		$this->assertNotNull($this->rule()->check($this->state(), $this->appTarget()), 'Still refused');
		$this->assertCount(1, $this->detections(), 'Recorded once per bucket');
		$this->assertSame(1, $this->detections()[0]->getHits());

		$this->now = self::NOW + 600;
		$this->assertNull($this->rule()->check($this->state(), $this->appTarget()), 'A new bucket starts from zero');
	}

	public function testTheNarrativeSaysWhatWasCountedAndDone(): void {
		for ($i = 0; $i <= 10; $i++) {
			$this->rule()->check($this->state(), $this->appTarget());
		}
		$l = Server::get(IFactory::class)->get(Application::APP_ID, 'en');
		$narrative = Server::get(NarrativeBuilder::class)->build($this->detections()[0], $l);
		$this->assertSame('Directory scraping', $narrative->title);
		$this->assertStringContainsString('The account alice made 11 searches for people within 10 minutes, from 203.0.113.9. The limit at that time was 10.', implode(' ', $narrative->happened));
		$this->assertStringContainsString('Further searches for people of the account were refused until', implode(' ', $narrative->done));
	}

	public function testEachKindOfRequestHasItsOwnCounter(): void {
		for ($i = 0; $i < 10; $i++) {
			$this->rule()->check($this->state(), $this->appTarget());
		}
		$this->route = 'core.avatar.getavatar';
		$this->assertNull($this->rule()->check($this->state(), $this->appTarget()), 'Avatars count separately, with their own limit');
		$this->assertNull($this->rule()->check($this->state(), RequestTarget::dav('REPORT', '/remote.php/dav/addressbooks/users/alice/z-server-generated--system/')));
		$this->route = 'ocs.core.autocomplete.get';
		$this->assertNotNull($this->rule()->check($this->state(), $this->appTarget()));
	}

	public function testWebDavPrincipalSearchesCountAsSearches(): void {
		for ($i = 0; $i < 10; $i++) {
			$this->assertNull($this->rule()->check($this->state(), RequestTarget::dav('REPORT', '/remote.php/dav/principals/')));
		}
		$this->assertNotNull($this->rule()->check($this->state(), $this->appTarget()), 'The 11th search, whichever way it came');
	}

	public function testObserveRecordsWhatWouldHaveHappenedAndRefusesNothing(): void {
		$this->settings->setMode(DirectoryScraping::ID, Mode::Observe);
		for ($i = 0; $i < 15; $i++) {
			$this->assertNull($this->rule()->check($this->state(), $this->appTarget()));
		}
		$detections = $this->detections();
		$this->assertCount(1, $detections);
		$this->assertFalse($detections[0]->isEnforced());
		foreach ($detections[0]->getActionList() as $action) {
			$this->assertFalse($action['enforced'], $action['type'] . ' would have run');
		}
	}

	public function testLearningModeOnlyObserves(): void {
		$this->settings->setGlobal(GlobalSettings::LEARNING_UNTIL, time() + 86400);
		for ($i = 0; $i < 12; $i++) {
			$this->assertNull($this->rule()->check($this->state(), $this->appTarget()));
		}
		$this->assertFalse($this->detections()[0]->isEnforced());
	}

	public function testWithoutTheRateLimitResponseNothingIsRefused(): void {
		$this->settings->setResponses(DirectoryScraping::ID, [ResponseType::NotifyAdmin]);
		for ($i = 0; $i < 12; $i++) {
			$this->assertNull($this->rule()->check($this->state(), $this->appTarget()));
		}
		$this->assertCount(1, $this->detections());
	}

	public function testOffCountsNothing(): void {
		$this->settings->setMode(DirectoryScraping::ID, Mode::Off);
		for ($i = 0; $i < 12; $i++) {
			$this->assertNull($this->rule()->check($this->state(), $this->appTarget()));
		}
		$this->assertSame(0, $this->cache->operations);
		$this->assertSame([], $this->detections());
	}

	public function testUnavailableWithoutAMemoryCache(): void {
		$settings = $this->settingsWith(false);
		$state = $settings->modeState(DirectoryScraping::ID);
		$this->assertSame(Mode::Off, $state->effective);
		$this->assertSame(ModeState::REASON_REQUIREMENT, $state->reason);
		$this->assertSame(Requirement::MemoryCache, $state->missing);
		try {
			$settings->setMode(DirectoryScraping::ID, Mode::Protect);
			$this->fail('The mode cannot be set without a memory cache');
		} catch (InvalidParamException $e) {
			$this->assertSame('mode_unavailable', $e->reason);
		}

		$factory = FixedCaches::none();
		$queries = $this->queries();
		for ($i = 0; $i < 12; $i++) {
			$this->assertNull($this->detector($settings, $factory)->count('alice', DirectoryRoutes::GROUP_SEARCH));
		}
		$this->assertSame(0, $this->queries() - $queries, 'Never counted in the database instead');
		$this->assertSame([], $this->detections());
	}

	public function testAStoredLimitOutOfRangeFallsBackToTheDefault(): void {
		Server::get(IAppConfig::class)->setValueInt(Application::APP_ID, 'check_directory_scraping_limit_search', 3);
		for ($i = 0; $i < 12; $i++) {
			$this->assertNull($this->rule()->check($this->state(), $this->appTarget()), 'The default limit of 200 applies');
		}
	}

	/**
	 * @return list<Detection>
	 */
	private function detections(): array {
		return Server::get(DetectionMapper::class)->findList(new DetectionFilter(checkIds: [DirectoryScraping::ID], limit: 10));
	}

	private function queries(): int {
		$connection = Server::get(IDBConnection::class);
		$this->assertInstanceOf(ConnectionAdapter::class, $connection);
		return $connection->getInner()->getStats()['executed'];
	}

	private function state(): SessionState {
		return new SessionState($this->createMock(ISession::class), $this->createMock(LoggerInterface::class));
	}

	private function appTarget(): RequestTarget {
		return RequestTarget::app($this->createMock(Controller::class), 'get', 'GET', '/ocs/v2.php/core/autocomplete/get');
	}

	private function rule(): DirectoryScrapingRule {
		$request = $this->request();
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn('alice');
		$userSession = $this->createMock(IUserSession::class);
		$userSession->method('getUser')->willReturn($user);
		$detector = $this->detector($this->settings, $this->cacheFactory());
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willReturnCallback(function (string $id) use ($detector): object {
			$this->built[] = $id;
			return $detector;
		});
		return new DirectoryScrapingRule($request, $userSession, $container);
	}

	private function detector(Settings $settings, Caches $factory): DirectoryScrapingDetector {
		$request = $this->request();
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturnCallback(fn (): int => $this->now);
		$context = new RequestContext();
		$context->setVerdict(new Verdict());
		$currentSession = $this->createMock(CurrentSession::class);
		$currentSession->method('tokenId')->willReturn(17);
		return new DirectoryScrapingDetector(
			$settings,
			$context,
			$factory,
			$time,
			new OverridingContainer([
				ResponseEngine::class => new ResponseEngine(
					Server::get(CheckRegistry::class),
					$settings,
					Server::get(DetectionService::class),
					Server::get(ContainerInterface::class),
					Server::get(TypedEvents::class),
					Server::get(AuditLogger::class),
					Server::get(LoggerInterface::class),
				),
				RemoteAddressResolver::class => new RemoteAddressResolver($request, Server::get(IThrottler::class), Server::get(ServerAddresses::class)),
				IRequest::class => $request,
				CurrentSession::class => $currentSession,
			]),
		);
	}

	private function request(): IRequest {
		$request = $this->createMock(IRequest::class);
		$request->method('getRemoteAddress')->willReturn('203.0.113.9');
		$request->method('getHeader')->willReturnCallback(static fn (string $name): string => $name === 'User-Agent' ? 'Mozilla/5.0 (test)' : '');
		$request->method('getParam')->willReturnCallback(fn (string $name): mixed => match ($name) {
			'_route' => $this->route,
			'providerId' => $this->providerId,
			default => null,
		});
		return $request;
	}

	private function cacheFactory(): Caches {
		return new FixedCaches($this->cache);
	}

	private function settingsWith(bool $memoryCache): Settings {
		$factory = $memoryCache ? new FixedCaches(new ArrayCache()) : FixedCaches::none();
		return new Settings(
			Server::get(IAppConfig::class),
			Server::get(CheckRegistry::class),
			Server::get(ITimeFactory::class),
			new Prerequisites($factory, Server::get(IConfig::class)),
			Server::get(GlobalSettings::class),
			Server::get(IEventDispatcher::class),
		);
	}
}

/**
 * An in-memory cache that counts what is asked of it.
 */
class OperationCountingCache extends ArrayCache {
	public int $operations = 0;
	/** @var array<string, int> */
	public array $byType = [];

	public function reset(): void {
		$this->operations = 0;
		$this->byType = [];
	}

	public function get($key) {
		$this->count('get');
		return parent::get($key);
	}

	public function set($key, $value, $ttl = 0) {
		$this->count('set');
		return parent::set($key, $value, $ttl);
	}

	public function add($key, $value, $ttl = 0) {
		$this->count('add');
		return parent::add($key, $value, $ttl);
	}

	public function inc($key, $step = 1) {
		$this->count('inc');
		$value = parent::get($key);
		$value = is_int($value) ? $value + $step : $step;
		parent::set($key, $value);
		return $value;
	}

	private function count(string $type): void {
		$this->operations++;
		$this->byType[$type] = ($this->byType[$type] ?? 0) + 1;
	}
}
