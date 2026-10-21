<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Breach;

use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Psr7\Request;
use OC\Memcache\ArrayCache;
use OCA\IntrusionDetection\Blocklist\LimitedSink;
use OCA\IntrusionDetection\Breach\PwnedPasswordsClient;
use OCP\Http\Client\IClient;
use OCP\Http\Client\IClientService;
use OCP\Http\Client\IResponse;
use OCP\ICacheFactory;
use OCP\Security\ICrypto;
use OCP\Server;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\AbstractLogger;
use Test\TestCase;

/**
 * The Pwned Passwords range client, against a mocked HTTP client: what is
 * sent, how answers are read, cached and given up on. Never contacts the
 * internet.
 */
class PwnedPasswordsClientTest extends TestCase {
	/** SHA-1 21BD12DC183F740EE76F27B78EB39C8AD972A757, the service's own example */
	private const PASSWORD = 'P@ssw0rd';
	private const PREFIX = '21BD1';
	private const SUFFIX = '2DC183F740EE76F27B78EB39C8AD972A757';

	/** @var IClientService&MockObject */
	private IClientService $clientService;
	/** @var IClient&MockObject */
	private IClient $client;
	/** @var ICacheFactory&MockObject */
	private ICacheFactory $cacheFactory;
	private ArrayCache $cache;
	/** @var list<string> */
	private array $logged = [];
	/** @var list<array{0: string, 1: array<string, mixed>}> */
	private array $requests = [];

	protected function setUp(): void {
		parent::setUp();
		$this->client = $this->createMock(IClient::class);
		$this->clientService = $this->createMock(IClientService::class);
		$this->clientService->method('newClient')->willReturn($this->client);
		$this->cache = new class extends ArrayCache {
			/** @return array<string, mixed> */
			public function all(): array {
				return $this->cachedData;
			}
		};
		$this->cacheFactory = $this->createMock(ICacheFactory::class);
		$this->cacheFactory->method('isAvailable')->willReturn(true);
		$this->cacheFactory->method('createDistributed')->willReturn($this->cache);
	}

	private function service(): PwnedPasswordsClient {
		return new PwnedPasswordsClient($this->clientService, $this->cacheFactory, Server::get(ICrypto::class), new class($this->logged) extends AbstractLogger {
			/** @param list<string> $lines */
			public function __construct(
				private array &$lines,
			) {
			}

			public function log($level, string|\Stringable $message, array $context = []): void {
				$this->lines[] = $message . ' ' . json_encode($context, JSON_PARTIAL_OUTPUT_ON_ERROR);
			}
		});
	}

	private function answer(string $body, int $status = 200): void {
		$response = $this->createMock(IResponse::class);
		$response->method('getStatusCode')->willReturn($status);
		$response->method('getBody')->willReturn($body);
		$this->client->method('get')->willReturnCallback(function (string $url, array $options) use ($response): IResponse {
			$this->requests[] = [$url, $options];
			return $response;
		});
	}

	private static function rangeBody(int $count): string {
		return implode("\r\n", [
			'0018A45C4D1DEF81644B54AB7F969B88D65:10',
			'00D4F6E8FA6EECAD2A3AA415EEC418D38EC:0',
			self::SUFFIX . ':' . $count,
			'011053FD0102E94D6AE2F8B83D76FAF94F6:3',
			'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0',
		]);
	}

	public function testSendsOnlyTheFivePrefixCharactersWithPadding(): void {
		$this->answer(self::rangeBody(52579));
		$this->assertSame(52579, $this->service()->count(self::PASSWORD));

		$this->assertCount(1, $this->requests);
		[$url, $options] = $this->requests[0];
		$this->assertSame('https://api.pwnedpasswords.com/range/21BD1', $url);
		$this->assertSame(['Add-Padding' => 'true', 'Accept' => 'text/plain'], $options['headers']);
		$this->assertSame(2, $options['timeout']);
		$this->assertSame(2, $options['connect_timeout']);
		$this->assertFalse($options['allow_redirects']);
		$this->assertFalse($options['http_errors']);
		$this->assertInstanceOf(LimitedSink::class, $options['sink']);
		$this->assertSame(['headers', 'timeout', 'connect_timeout', 'allow_redirects', 'http_errors', 'sink'], array_keys($options), 'Nothing else is sent');
		$sent = json_encode([$url, $options['headers']]);
		$this->assertStringNotContainsString(self::SUFFIX, $sent);
		$this->assertStringNotContainsString(self::PASSWORD, $sent);
	}

	public function testAPasswordNotInTheRangeCountsZero(): void {
		$this->answer(self::rangeBody(52579));
		$this->assertSame(0, $this->service()->count('Not-in-the-list-' . bin2hex(random_bytes(8))));
	}

	public function testPaddingEntriesCountZero(): void {
		$this->answer(self::rangeBody(0));
		$this->assertSame(0, $this->service()->count(self::PASSWORD));
	}

	public function testParsesLinesAndIgnoresMalformedOnes(): void {
		$this->assertSame(
			['0018A45C4D1DEF81644B54AB7F969B88D65' => 10, self::SUFFIX => 7],
			PwnedPasswordsClient::parse("0018A45C4D1DEF81644B54AB7F969B88D65:10\r\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:0\nnot a line\n" . strtolower(self::SUFFIX) . ":4\n" . self::SUFFIX . ":7\nABC:1\n" . self::SUFFIX . ":12345678901234\n"),
		);
		$this->assertSame([], PwnedPasswordsClient::parse("00D4F6E8FA6EECAD2A3AA415EEC418D38EC:0\n"), 'A range of padding only is a valid, empty range');
		$this->assertNull(PwnedPasswordsClient::parse('<html>Service unavailable</html>'));
		$this->assertNull(PwnedPasswordsClient::parse(''));
	}

	public function testAnswersAreCachedPerRangeForADay(): void {
		$this->answer(self::rangeBody(52579));
		$this->assertSame(52579, $this->service()->count(self::PASSWORD));
		$this->assertCount(1, $this->requests);
		$this->requests = [];

		// A fresh client (another request) reads the cached range.
		$this->assertSame(52579, $this->service()->count(self::PASSWORD));
		$this->assertSame([], $this->requests, 'The second check does not contact the service');
	}

	public function testTheCacheRevealsNeitherTheRangeNorItsContent(): void {
		$this->answer(self::rangeBody(52579));
		$this->service()->count(self::PASSWORD);

		$entries = $this->cache->all();
		$this->assertCount(1, $entries);
		$key = (string)array_key_first($entries);
		$value = (string)$entries[$key];
		$this->assertMatchesRegularExpression('/^hibp:[0-9a-f]{32}$/', $key);
		foreach ([self::PREFIX, strtolower(self::PREFIX), self::SUFFIX, '52579', self::PASSWORD] as $secret) {
			$this->assertStringNotContainsString($secret, $key);
			$this->assertStringNotContainsString($secret, $value);
		}
	}

	public function testCachesWithTheTtlOfADay(): void {
		$cache = $this->createMock(\OCP\ICache::class);
		$cache->method('get')->willReturn(null);
		$cache->expects($this->once())->method('set')->with($this->stringStartsWith('hibp:'), $this->isType('string'), 86400);
		$factory = $this->createMock(ICacheFactory::class);
		$factory->method('isAvailable')->willReturn(true);
		$factory->method('createDistributed')->willReturn($cache);
		$this->cacheFactory = $factory;
		$this->answer(self::rangeBody(1));
		$this->assertSame(1, $this->service()->count(self::PASSWORD));
	}

	public function testUsesTheLocalCacheWithoutADistributedOne(): void {
		$factory = $this->createMock(ICacheFactory::class);
		$factory->method('isAvailable')->willReturn(false);
		$factory->method('isLocalCacheAvailable')->willReturn(true);
		$factory->expects($this->never())->method('createDistributed');
		$factory->expects($this->once())->method('createLocal')->willReturn($this->cache);
		$this->cacheFactory = $factory;
		$this->answer(self::rangeBody(3));
		$service = $this->service();
		$this->assertSame(3, $service->count(self::PASSWORD));
		$this->assertSame(3, $service->count(self::PASSWORD));
		$this->assertCount(1, $this->requests);
	}

	public function testWithoutAnyMemoryCacheEveryCheckAsks(): void {
		$factory = $this->createMock(ICacheFactory::class);
		$factory->method('isAvailable')->willReturn(false);
		$factory->method('isLocalCacheAvailable')->willReturn(false);
		$this->cacheFactory = $factory;
		$this->answer(self::rangeBody(3));
		$service = $this->service();
		$service->count(self::PASSWORD);
		$service->count(self::PASSWORD);
		$this->assertCount(2, $this->requests);
	}

	public function testAnUnreadableCacheEntryIsAMiss(): void {
		$this->answer(self::rangeBody(8));
		$this->service()->count(self::PASSWORD);
		$key = (string)array_key_first($this->cache->all());
		$this->cache->set($key, 'garbage|00|00|3');
		$this->assertSame(8, $this->service()->count(self::PASSWORD));
		$this->assertCount(2, $this->requests);
	}

	public function testFailsOpenOnATimeoutWithoutLoggingTheAddress(): void {
		$this->client->method('get')->willThrowException(new ConnectException(
			'cURL error 28: Operation timed out after 2001 milliseconds for https://api.pwnedpasswords.com/range/' . self::PREFIX,
			new Request('GET', 'https://api.pwnedpasswords.com/range/' . self::PREFIX),
		));
		$this->assertNull($this->service()->count(self::PASSWORD));
		$this->assertSame([], $this->cache->all(), 'Nothing is cached');
		$this->assertCount(1, $this->logged);
		$this->assertStringContainsString('ConnectException', $this->logged[0]);
		$this->assertStringNotContainsString(self::PREFIX, $this->logged[0]);
	}

	public function testFailsOpenOnAServerError(): void {
		$this->answer('Service unavailable', 503);
		$this->assertNull($this->service()->count(self::PASSWORD));
		$this->assertSame([], $this->cache->all());
		$this->assertStringContainsString('503', $this->logged[0]);
	}

	public function testFailsOpenOnAMalformedAnswer(): void {
		$this->answer('<html>Rate limit exceeded</html>');
		$this->assertNull($this->service()->count(self::PASSWORD));
		$this->assertSame([], $this->cache->all());
	}

	public function testRefusesAnAnswerAboveTheSizeLimit(): void {
		$this->answer(str_repeat(self::SUFFIX . ":1\n", intdiv(PwnedPasswordsClient::MAX_BYTES, 38) + 10));
		$this->assertNull($this->service()->count(self::PASSWORD));
	}

	public function testFailsOpenWhenTheSinkAbortsTheTransfer(): void {
		$this->client->method('get')->willReturnCallback(static function (string $url, array $options): IResponse {
			$options['sink']->write(str_repeat('A', PwnedPasswordsClient::MAX_BYTES + 1));
			throw new \LogicException('not reached');
		});
		$this->assertNull($this->service()->count(self::PASSWORD));
		$this->assertStringContainsString('SyncFailure', $this->logged[0]);
	}
}
