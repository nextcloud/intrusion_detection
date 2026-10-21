<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\Uri;
use OCA\IntrusionDetection\Address\AddressCache;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Blocklist\BlocklistFactsProvider;
use OCA\IntrusionDetection\Blocklist\BlocklistOverview;
use OCA\IntrusionDetection\Blocklist\BlocklistSync;
use OCA\IntrusionDetection\Blocklist\LimitedSink;
use OCA\IntrusionDetection\Blocklist\SourceRepository;
use OCA\IntrusionDetection\Blocklist\StateStore;
use OCA\IntrusionDetection\Blocklist\SyncFailure;
use OCA\IntrusionDetection\Blocklist\SyncResult;
use OCA\IntrusionDetection\Blocklist\UrlPolicy;
use OCA\IntrusionDetection\Check\Checks\BlocklistMatch;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\BlocklistRangeMapper;
use OCA\IntrusionDetection\Db\BlocklistStatMapper;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\SetupCheck\BlocklistSyncCheck;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Http\Client\IClient;
use OCP\Http\Client\IClientService;
use OCP\Http\Client\IResponse;
use OCP\ICacheFactory;
use OCP\IDBConnection;
use OCP\IL10N;
use OCP\Lock\ILockingProvider;
use OCP\Lock\LockedException;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;

/**
 * The list download, with a mocked HTTP client: nothing here contacts the internet.
 */
#[Group('DB')]
class BlocklistSyncTest extends IntegrationTestCase {
	private const URL = 'https://lists.example.org/block.txt';
	private const TOR_URL = 'https://lists.example.org/tor.txt';

	private int $now = 1792490400;
	/** @var array<string, list<array{status: int, body: string, headers: array<string, string>}|\Throwable>> */
	private array $responses = [];
	/** @var list<array{url: string, options: array<string, mixed>}> */
	private array $requests = [];
	private ?\Closure $duringWrite = null;
	private Settings $settings;

	protected function setUp(): void {
		parent::setUp();
		$this->settings = Server::get(Settings::class);
		$this->settings->setMode(BlocklistMatch::ID, Mode::Protect);
		$this->setSources([
			['id' => 'office_block', 'url' => self::URL, 'purpose' => 'deny', 'mode' => 'protect', 'enabled' => true],
		]);
	}

	public function testASyncWritesANewVersionAndSwitchesToIt(): void {
		$this->respond(self::URL, 200, $this->fixture('custom.txt'), ['Last-Modified' => 'Tue, 20 Oct 2026 08:00:00 GMT', 'ETag' => '"abc"']);
		$cacheVersion = $this->appConfig->getValueInt(Application::APP_ID, GlobalSettings::BAN_VERSION);

		[$result] = $this->sync()->sync();

		$this->assertSame(SyncResult::UPDATED, $result->outcome);
		$this->assertSame(3, $result->ranges);
		$state = $this->states()->get('office_block');
		$this->assertSame(1, $state->version);
		$this->assertSame(3, $state->ranges);
		$this->assertSame($this->now, $state->successAt);
		$this->assertSame('Tue, 20 Oct 2026 08:00:00 GMT', $state->lastModified);
		$this->assertSame(3, $this->ranges()->countVersion('office_block', 1));
		$this->assertNotSame($cacheVersion, $this->appConfig->getValueInt(Application::APP_ID, GlobalSettings::BAN_VERSION), 'Cached verdicts are invalidated');
	}

	public function testTheDownloadIsLimitedAndRefusesLocalRedirects(): void {
		$this->respond(self::URL, 200, $this->fixture('custom.txt'));
		$this->sync()->sync();

		$options = $this->requests[0]['options'];
		$this->assertSame(self::URL, $this->requests[0]['url']);
		$this->assertInstanceOf(LimitedSink::class, $options['sink']);
		try {
			$options['sink']->write(str_repeat('a', BlocklistSync::MAX_BYTES + 1));
			$this->fail('The sink must refuse more than the limit');
		} catch (SyncFailure $e) {
			$this->assertSame(SyncFailure::TOO_LARGE, $e->reason);
		}
		$big = new Response(200, ['Content-Length' => (string)(BlocklistSync::MAX_BYTES + 1)]);
		try {
			$options['on_headers']($big);
			$this->fail('A declared length above the limit must abort the download');
		} catch (SyncFailure $e) {
			$this->assertSame(SyncFailure::TOO_LARGE, $e->reason);
		}
		$options['on_headers'](new Response(200, ['Content-Length' => '1000']));
		$this->assertLessThanOrEqual(60, $options['timeout']);
		$this->assertLessThanOrEqual(10, $options['connect_timeout']);
		$this->assertSame(['https'], $options['allow_redirects']['protocols']);
		$this->assertLessThanOrEqual(3, $options['allow_redirects']['max']);
		$this->assertArrayNotHasKey('nextcloud', $options, 'Local addresses stay forbidden');

		$onRedirect = $options['allow_redirects']['on_redirect'];
		$onRedirect(null, null, new Uri('https://mirror.example.org/block.txt'));
		foreach (['https://127.0.0.1/x', 'https://localhost/x', 'https://[::1]/x', 'https://192.168.1.1/x', 'http://mirror.example.org/x'] as $target) {
			try {
				$onRedirect(null, null, new Uri($target));
				$this->fail('Redirect to ' . $target . ' must be refused');
			} catch (SyncFailure $e) {
				$this->assertSame(SyncFailure::URL_REFUSED, $e->reason);
			}
		}
	}

	public function testAnUnchangedListIsNotDownloadedAgain(): void {
		$this->respond(self::URL, 200, $this->fixture('custom.txt'), ['Last-Modified' => 'Tue, 20 Oct 2026 08:00:00 GMT', 'ETag' => '"abc"']);
		$this->respond(self::URL, 304, '');
		$this->respond(self::URL, 200, $this->fixture('custom.txt'));
		$this->sync()->sync();
		$this->now += 3600;

		[$result] = $this->sync()->sync();
		$this->assertSame(SyncResult::UNCHANGED, $result->outcome);
		$this->assertSame('Tue, 20 Oct 2026 08:00:00 GMT', $this->requests[1]['options']['headers']['If-Modified-Since']);
		$this->assertSame('"abc"', $this->requests[1]['options']['headers']['If-None-Match']);
		$this->assertSame(1, $this->states()->get('office_block')->version);
		$this->assertSame($this->now, $this->states()->get('office_block')->successAt);

		[$forced] = $this->sync()->sync('office_block', true);
		$this->assertSame(SyncResult::UPDATED, $forced->outcome);
		$this->assertArrayNotHasKey('If-Modified-Since', $this->requests[2]['options']['headers']);
	}

	public function testAListWithTooManyEntriesIsRefusedAndTheOldVersionStays(): void {
		$this->settings->setGlobal(GlobalSettings::BLOCKLIST_MAX_ENTRIES, 100);
		$this->respond(self::URL, 200, $this->fixture('custom.txt'));
		$this->respond(self::URL, 200, self::lines(101));
		$this->sync()->sync();

		[$result] = $this->sync()->sync('office_block', true);

		$this->assertSame(SyncResult::FAILED, $result->outcome);
		$this->assertSame(SyncFailure::TOO_MANY_ENTRIES, $result->error);
		$state = $this->states()->get('office_block');
		$this->assertSame(1, $state->version, 'The previous version stays in use');
		$this->assertSame(SyncFailure::TOO_MANY_ENTRIES, $state->error);
		$this->assertSame(1, $state->failures);
		$this->assertSame(3, $this->ranges()->countVersion('office_block', 1));
	}

	public function testUpToOnePercentMalformedLinesAreAccepted(): void {
		$this->respond(self::URL, 200, self::lines(100) . "garbage\n");
		[$result] = $this->sync()->sync();
		$this->assertSame(SyncResult::UPDATED, $result->outcome);
		$this->assertSame(1, $this->states()->get('office_block')->malformed);
	}

	public function testMoreThanOnePercentMalformedLinesAreRefused(): void {
		$this->respond(self::URL, 200, self::lines(98) . "garbage\n<html>\n");
		[$result] = $this->sync()->sync();
		$this->assertSame(SyncFailure::TOO_MANY_MALFORMED, $result->error);
		$this->assertNull($this->states()->get('office_block')->version);
		$this->assertSame([], $this->ranges()->listIds());
	}

	public function testALargeAnswerIsRefusedByItsLength(): void {
		$this->respond(self::URL, 200, '192.0.2.0/24', ['Content-Length' => (string)(BlocklistSync::MAX_BYTES + 1)]);
		[$result] = $this->sync()->sync();
		$this->assertSame(SyncFailure::TOO_LARGE, $result->error);
	}

	public function testALargeAnswerIsRefusedWhileReading(): void {
		$this->respond(self::URL, 200, str_repeat("192.0.2.0/24\n", intdiv(BlocklistSync::MAX_BYTES, 13) + 1));
		[$result] = $this->sync()->sync();
		$this->assertSame(SyncFailure::TOO_LARGE, $result->error);
	}

	public function testAFailureWrappedByTheHttpClientKeepsItsReason(): void {
		$this->respond(self::URL, new \RuntimeException('Request aborted', 0, new SyncFailure(SyncFailure::TOO_LARGE)));
		[$result] = $this->sync()->sync();
		$this->assertSame(SyncFailure::TOO_LARGE, $result->error);
	}

	public function testOtherFailuresAreRecorded(): void {
		$this->respond(self::URL, 500, 'oops');
		$this->respond(self::URL, 200, "# only comments\n");
		$this->respond(self::URL, new \RuntimeException('connection refused'));
		$this->setSources([
			['id' => 'office_block', 'url' => self::URL, 'purpose' => 'deny', 'enabled' => true],
			['id' => 'aws_copy', 'url' => 'https://lists.example.org/aws.json', 'purpose' => 'hosting', 'format' => 'aws_json', 'enabled' => true],
		]);
		$this->respond('https://lists.example.org/aws.json', 200, 'not json');

		$results = $this->sync()->sync();
		$this->assertSame([SyncFailure::HTTP, SyncFailure::INVALID_FORMAT], array_map(static fn (SyncResult $r): ?string => $r->error, $results));
		$this->assertSame(SyncFailure::EMPTY, $this->sync()->sync('office_block')[0]->error);
		$this->assertSame(SyncFailure::NETWORK, $this->sync()->sync('office_block')[0]->error);
		$this->assertSame(3, $this->states()->get('office_block')->failures);
	}

	public function testLocalAndPlainHttpAddressesAreNeverContacted(): void {
		$this->setSources([
			['id' => 'loopback', 'url' => 'https://127.0.0.1/list.txt', 'purpose' => 'deny', 'enabled' => true],
			['id' => 'local_name', 'url' => 'https://localhost/list.txt', 'purpose' => 'tor', 'enabled' => true],
			['id' => 'private_net', 'url' => 'https://10.1.2.3/list.txt', 'purpose' => 'hosting', 'enabled' => true],
		]);
		$results = $this->sync()->sync();
		$this->assertCount(3, $results);
		foreach ($results as $result) {
			$this->assertSame(SyncFailure::URL_REFUSED, $result->error, $result->listId);
		}
		$this->assertSame([], $this->requests);

		// A plain http:// address is not even read as a list.
		$this->setSources([['id' => 'plain', 'url' => 'http://lists.example.org/x.txt', 'purpose' => 'deny', 'enabled' => true]]);
		$this->assertSame([], $this->sync()->sync());
	}

	public function testAReaderDuringASyncSeesTheOldOrTheNewListNeverAMix(): void {
		$this->respond(self::URL, 200, "192.0.2.0/24\n");
		$this->respond(self::URL, 200, "198.51.100.0/24\n");
		$this->sync()->sync();
		$old = SourceKey::fromIp('192.0.2.7');
		$new = SourceKey::fromIp('198.51.100.7');
		$this->assertTrue($this->provider()->facts($old)->denyUntil > 0);
		$this->assertSame(0, $this->provider()->facts($new)->denyUntil);

		$seen = null;
		$this->duringWrite = function () use ($old, $new, &$seen): void {
			// The new version is written completely, but not switched to yet.
			$seen = [$this->provider()->facts($old)->denyUntil > 0, $this->provider()->facts($new)->denyUntil > 0];
		};
		$this->sync()->sync();

		$this->assertSame([true, false], $seen, 'While writing, readers see the old list only');
		$this->assertSame(0, $this->provider()->facts($old)->denyUntil);
		$this->assertTrue($this->provider()->facts($new)->denyUntil > 0, 'After the switch, readers see the new list only');
	}

	public function testThePreviousVersionIsKeptForAGracePeriod(): void {
		$this->respond(self::URL, 200, "192.0.2.0/24\n");
		$this->respond(self::URL, 200, "198.51.100.0/24\n");
		$this->respond(self::URL, 200, "203.0.113.0/24\n");
		$this->sync()->sync();
		$this->sync()->sync();
		$this->assertSame(1, $this->ranges()->countVersion('office_block', 1), 'Still there for readers that started before the switch');

		$this->now += BlocklistSync::PREVIOUS_GRACE;
		$this->sync()->cleanup();
		$this->assertSame(0, $this->ranges()->countVersion('office_block', 1));
		$this->assertSame(1, $this->ranges()->countVersion('office_block', 2));
		$this->assertNull($this->states()->get('office_block')->previous);

		$this->sync()->sync();
		$this->assertSame(3, $this->states()->get('office_block')->version);
	}

	public function testLeftoversOfAnInterruptedSyncAreRemoved(): void {
		$this->respond(self::URL, 200, "192.0.2.0/24\n");
		$this->sync()->sync();
		$this->ranges()->writeVersion('office_block', 7, ['4' . str_repeat('0', 64)]);
		$this->sync()->cleanup();
		$this->assertSame(0, $this->ranges()->countVersion('office_block', 7));
		$this->assertSame(1, $this->ranges()->countVersion('office_block', 1));
	}

	public function testASwitchedOffListLosesItsRangesAndARemovedOneEverything(): void {
		$this->respond(self::URL, 200, "192.0.2.0/24\n");
		$this->sync()->sync();
		Server::get(BlocklistStatMapper::class)->record('office_block', '2026-10-20', '192.0.2.7');

		$this->setSources([['id' => 'office_block', 'url' => self::URL, 'purpose' => 'deny', 'enabled' => false]]);
		$this->sync()->cleanup();
		$this->assertSame([], $this->ranges()->listIds());
		$state = $this->states()->get('office_block');
		$this->assertNull($state->version);
		$this->assertSame($this->now, $state->successAt, 'The sync history stays');

		$this->setSources([]);
		$this->sync()->cleanup();
		$this->assertArrayNotHasKey('office_block', $this->states()->all());
		$this->assertNull(Server::get(BlocklistStatMapper::class)->find('office_block', '2026-10-20'));
	}

	public function testDueListsFollowTheirIntervalsAndBlocklistsWaitWhileTheCheckIsOff(): void {
		$this->setSources([
			['id' => 'office_block', 'url' => self::URL, 'purpose' => 'deny', 'enabled' => true],
			['id' => 'tor_copy', 'url' => self::TOR_URL, 'purpose' => 'tor', 'enabled' => true, 'interval' => 3600],
		]);
		$this->respond(self::URL, 200, "192.0.2.0/24\n");
		$this->respond(self::TOR_URL, 200, "198.51.100.7\n");
		$this->respond(self::TOR_URL, 200, "198.51.100.8\n");
		$this->assertCount(2, $this->sync()->syncDue());
		$this->assertSame([], $this->sync()->syncDue(), 'Nothing is due right after a sync');

		$this->now += 3600;
		$results = $this->sync()->syncDue();
		$this->assertSame(['tor_copy'], array_map(static fn (SyncResult $r): string => $r->listId, $results), 'Only the hourly list is due');

		$this->settings->setMode(BlocklistMatch::ID, Mode::Off);
		$this->now += 86400;
		$this->respond(self::TOR_URL, 200, "198.51.100.9\n");
		$results = $this->sync()->syncDue();
		$this->assertSame(['tor_copy'], array_map(static fn (SyncResult $r): string => $r->listId, $results), 'Blocklists are not downloaded while their check is off');
	}

	public function testAListFailingForMoreThanThreeIntervalsIsReported(): void {
		$this->settings->setGlobal(GlobalSettings::BLOCKLIST_SYNC_INTERVAL, 3600);
		$this->respond(self::URL, 200, "192.0.2.0/24\n");
		$this->sync()->sync();
		for ($i = 0; $i < 4; $i++) {
			$this->now += 3600;
			$this->respond(self::URL, 503, '');
			$this->sync()->sync();
			$stale = $this->overview()->stale();
			if ($i < 2) {
				$this->assertSame([], $stale, 'Not yet after ' . ($i + 1) . ' failed intervals');
			}
		}
		$this->assertSame(['office_block'], array_map(static fn (array $l): string => $l['id'], $this->overview()->stale()));
		$l10n = $this->createMock(IL10N::class);
		$l10n->method('t')->willReturnCallback(static fn (string $text, array $p = []): string => vsprintf($text, $p));
		$l10n->method('n')->willReturnCallback(static fn (string $s, string $p, int $n, array $params = []): string => vsprintf(str_replace('%n', (string)$n, $n === 1 ? $s : $p), $params));
		$result = (new BlocklistSyncCheck($this->overview(), $l10n))->run();
		$this->assertSame('warning', $result->getSeverity());
		$this->assertStringContainsString('office_block', (string)$result->getDescription());

		$this->now += 3600;
		$this->respond(self::URL, 200, "192.0.2.0/24\n");
		$this->sync()->sync();
		$this->assertSame([], $this->overview()->stale());
		$this->assertSame('success', (new BlocklistSyncCheck($this->overview(), $l10n))->run()->getSeverity());
	}

	public function testASyncThatIsAlreadyRunningIsSkipped(): void {
		$locking = $this->createMock(ILockingProvider::class);
		$locking->method('acquireLock')->willThrowException(new LockedException('intrusion_detection/blocklist_sync'));
		[$result] = $this->sync($locking)->sync();
		$this->assertSame(SyncResult::SKIPPED, $result->outcome);
		$this->assertSame([], $this->requests);
	}

	public function testOldMatchCountersAreDeleted(): void {
		$stats = Server::get(BlocklistStatMapper::class);
		$stats->record('office_block', gmdate('Y-m-d', $this->now - 31 * 86400), '192.0.2.7');
		$stats->record('office_block', gmdate('Y-m-d', $this->now - 29 * 86400), '192.0.2.7');
		$this->sync()->cleanup();
		$this->assertNull($stats->find('office_block', gmdate('Y-m-d', $this->now - 31 * 86400)));
		$this->assertNotNull($stats->find('office_block', gmdate('Y-m-d', $this->now - 29 * 86400)));
	}

	/**
	 * @param list<array<string, mixed>> $sources
	 */
	private function setSources(array $sources): void {
		$this->settings->setGlobal(GlobalSettings::BLOCKLIST_SOURCES, json_encode($sources));
	}

	/**
	 * @param array<string, string> $headers
	 */
	private function respond(string $url, int|\Throwable $status, string $body = '', array $headers = []): void {
		$this->responses[$url][] = $status instanceof \Throwable ? $status : ['status' => $status, 'body' => $body, 'headers' => $headers];
	}

	private function sync(?ILockingProvider $locking = null): BlocklistSync {
		$client = $this->createMock(IClient::class);
		$client->method('get')->willReturnCallback(function (string $url, array $options): IResponse {
			$this->requests[] = ['url' => $url, 'options' => $options];
			$next = array_shift($this->responses[$url]) ?? throw new \RuntimeException('No response for ' . $url);
			if ($next instanceof \Throwable) {
				throw $next;
			}
			$body = fopen('php://memory', 'r+b');
			fwrite($body, $next['body']);
			rewind($body);
			$response = $this->createMock(IResponse::class);
			$response->method('getStatusCode')->willReturn($next['status']);
			$response->method('getBody')->willReturn($body);
			$response->method('getHeader')->willReturnCallback(static fn (string $name): string => $next['headers'][$name] ?? '');
			return $response;
		});
		$clientService = $this->createMock(IClientService::class);
		$clientService->method('newClient')->willReturn($client);

		$test = $this;
		$ranges = new class(Server::get(IDBConnection::class), $test) extends BlocklistRangeMapper {
			public function __construct(
				IDBConnection $db,
				private readonly BlocklistSyncTest $test,
			) {
				parent::__construct($db);
			}

			#[\Override]
			public function writeVersion(string $listId, int $version, array $ranges): void {
				parent::writeVersion($listId, $version, $ranges);
				$this->test->afterWrite();
			}
		};

		return new BlocklistSync(
			Server::get(SourceRepository::class),
			$this->states(),
			$ranges,
			Server::get(BlocklistStatMapper::class),
			$clientService,
			Server::get(UrlPolicy::class),
			$this->settings,
			$this->addressCache(),
			$locking ?? Server::get(ILockingProvider::class),
			$this->time(),
			Server::get(LoggerInterface::class),
		);
	}

	/**
	 * Called by the range mapper after a version is written, before the switch.
	 */
	public function afterWrite(): void {
		if ($this->duringWrite !== null) {
			($this->duringWrite)();
		}
	}

	private function provider(): BlocklistFactsProvider {
		return new BlocklistFactsProvider(
			Server::get(SourceRepository::class),
			$this->states(),
			$this->ranges(),
			Server::get(BlocklistStatMapper::class),
			$this->settings,
			$this->addressCache(),
			$this->time(),
			Server::get(LoggerInterface::class),
		);
	}

	private function overview(): BlocklistOverview {
		return new BlocklistOverview(Server::get(SourceRepository::class), $this->states(), Server::get(BlocklistStatMapper::class), $this->settings, $this->time(), $this->addressCache());
	}

	private function states(): StateStore {
		return Server::get(StateStore::class);
	}

	private function ranges(): BlocklistRangeMapper {
		return Server::get(BlocklistRangeMapper::class);
	}

	private function addressCache(): AddressCache {
		$factory = $this->createMock(ICacheFactory::class);
		$factory->method('isAvailable')->willReturn(false);
		$factory->method('isLocalCacheAvailable')->willReturn(false);
		return new AddressCache($factory, $this->appConfig);
	}

	private function time(): ITimeFactory {
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturnCallback(fn (): int => $this->now);
		return $time;
	}

	private static function lines(int $count): string {
		$lines = '';
		for ($i = 0; $i < $count; $i++) {
			$lines .= '203.0.' . intdiv($i, 250) . '.' . ($i % 250) . "\n";
		}
		return $lines;
	}

	private function fixture(string $name): string {
		return (string)file_get_contents(__DIR__ . '/../fixtures/blocklists/' . $name);
	}
}
