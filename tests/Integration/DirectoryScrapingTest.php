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
use OCA\IntrusionDetection\Check\Checks\DirectoryScraping\DirectoryCounter;
use OCA\IntrusionDetection\Check\Checks\DirectoryScraping\DirectoryScraping;
use OCA\IntrusionDetection\Check\Checks\DirectoryScraping\DirectoryScrapingFacts;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Config\CoreHooks;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Config\Prerequisites;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
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
use OCA\IntrusionDetection\Login\CoreSession;
use OCA\IntrusionDetection\Login\RequestContext;
use OCA\IntrusionDetection\Login\SessionMarkers;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\ServerAddresses;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCA\IntrusionDetection\Sensitive\DirectoryRoutes;
use OCA\IntrusionDetection\SessionState\RequestTarget;
use OCA\IntrusionDetection\SessionState\Rules\DirectoryScrapingRule;
use OCA\IntrusionDetection\SessionState\SessionBlock;
use OCA\IntrusionDetection\Tests\Unit\Cache\FixedCaches;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Utility\ITimeFactory;
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
	private CheckSettings $settings;
	private int $now = self::NOW;
	private string $route = 'ocs.core.autocomplete.get';
	private ?string $providerId = null;
	/** @var list<string> services the rule asked the container for */
	private array $built = [];

	protected function setUp(): void {
		parent::setUp();
		$this->cache = new OperationCountingCache();
		$this->settings = $this->settingsWith(true);
		$this->settingsEditor()->setParam(DirectoryScraping::ID, 'limit_search', 10);
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

	public function testAMatchingRequestCostsTwoCacheOperationsAndNoQuery(): void {
		$this->rule()->check($this->state(), $this->appTarget());
		$this->assertSame(['add' => 1, 'set' => 1, 'inc' => 1], $this->cache->byType, 'The first request of a bucket creates the counter with its lifetime, then counts');
		$queries = $this->queries();
		$this->cache->reset();
		for ($i = 0; $i < 5; $i++) {
			$this->assertNull($this->rule()->check($this->state(), $this->appTarget()));
		}
		$this->assertSame(['add' => 5, 'inc' => 5], $this->cache->byType, 'One add that finds the counter, and one increment, per request');
		$this->assertSame(0, $this->queries() - $queries, 'No database query');
	}

	public function testACountBetweenTheFirstIncrementAndItsLifetimeIsNotLost(): void {
		$counter = $this->detector($this->settings, $this->cacheFactory());
		$counted = null;
		// Another web server counts right after this request's first increment.
		$this->cache->afterInc = function (string $key) use (&$counted): void {
			$counted = $key;
			$this->cache->inc($key);
		};
		$counter->count('alice', DirectoryRoutes::GROUPS[0]);
		$counter->count('alice', DirectoryRoutes::GROUPS[0]);
		$this->assertIsString($counted);
		$this->assertSame(3, $this->cache->get($counted), 'all three requests are counted');
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
		$facts = DirectoryScrapingFacts::fromArray($detection->getExplanationData()['facts']);
		$this->assertSame(DirectoryRoutes::GROUP_SEARCH, $facts->group);
		$this->assertSame(11, $facts->count);
		$this->assertSame(10, $facts->limit);
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
		$this->settingsEditor()->setMode(DirectoryScraping::ID, Mode::Observe);
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
		$this->settingsEditor()->setGlobal(GlobalSettings::LEARNING_UNTIL, time() + 86400);
		for ($i = 0; $i < 12; $i++) {
			$this->assertNull($this->rule()->check($this->state(), $this->appTarget()));
		}
		$this->assertFalse($this->detections()[0]->isEnforced());
	}

	public function testWithoutTheRateLimitResponseNothingIsRefused(): void {
		$this->settingsEditor()->setResponses(DirectoryScraping::ID, [ResponseType::NotifyAdmin]);
		for ($i = 0; $i < 12; $i++) {
			$this->assertNull($this->rule()->check($this->state(), $this->appTarget()));
		}
		$this->assertCount(1, $this->detections());
	}

	public function testOffCountsNothing(): void {
		$this->settingsEditor()->setMode(DirectoryScraping::ID, Mode::Off);
		for ($i = 0; $i < 12; $i++) {
			$this->assertNull($this->rule()->check($this->state(), $this->appTarget()));
		}
		$this->assertSame(0, $this->cache->operations);
		$this->assertSame([], $this->detections());
	}

	public function testUnavailableWithoutAMemoryCache(): void {
		[$settings, $editor] = $this->settingsOn(new Prerequisites(FixedCaches::none(), Server::get(IConfig::class), new CoreHooks()));
		$state = $settings->modeState(DirectoryScraping::ID);
		$this->assertSame(Mode::Off, $state->effective);
		$this->assertSame(ModeState::REASON_REQUIREMENT, $state->reason);
		$this->assertSame(Requirement::MemoryCache, $state->missing);
		try {
			$editor->setMode(DirectoryScraping::ID, Mode::Protect);
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

	private function state(): SessionMarkers {
		return new SessionMarkers($this->createMock(ISession::class), $this->createMock(LoggerInterface::class));
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

	private function detector(CheckSettings $settings, Caches $factory): DirectoryCounter {
		$request = $this->request();
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturnCallback(fn (): int => $this->now);
		$context = new RequestContext();
		$context->set(Verdict::CONTEXT_KEY, new Verdict());
		$coreSession = $this->createMock(CoreSession::class);
		$coreSession->method('tokenId')->willReturn(17);
		return new DirectoryCounter(
			$this->appSettings(),
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
				CoreSession::class => $coreSession,
			]),
			Server::get(Fingerprinter::class),
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

	private function settingsWith(bool $memoryCache): CheckSettings {
		return $this->settingsOn(new Prerequisites($memoryCache ? new FixedCaches(new ArrayCache()) : FixedCaches::none(), Server::get(IConfig::class), new CoreHooks()))[0];
	}
}

/**
 * An in-memory cache that counts what is asked of it.
 */
class OperationCountingCache extends ArrayCache {
	public int $operations = 0;
	/** @var array<string, int> */
	public array $byType = [];
	/** @var ?\Closure(string): void runs once after the next increment, as another web server would */
	public ?\Closure $afterInc = null;

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
		$after = $this->afterInc;
		$this->afterInc = null;
		if ($after !== null) {
			$after($key);
		}
		return $value;
	}

	private function count(string $type): void {
		$this->operations++;
		$this->byType[$type] = ($this->byType[$type] ?? 0) + 1;
	}
}
