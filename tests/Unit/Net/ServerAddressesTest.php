<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Net;

use OCA\IntrusionDetection\Net\ServerAddresses;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\State\HotState;
use OCP\IAppConfig;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;

class ServerAddressesTest extends TestCase {
	private IAppConfig&MockObject $appConfig;
	/** @var list<string> */
	private array $stored = [];
	private int $writes = 0;

	protected function setUp(): void {
		parent::setUp();
		$this->appConfig = $this->createMock(IAppConfig::class);
		$this->appConfig->method('getValueArray')->willReturnCallback(fn (string $app, string $key): array => $key === HotState::SERVER_ADDRESSES ? $this->stored : []);
		$this->appConfig->method('setValueArray')->willReturnCallback(function (string $app, string $key, array $value): bool {
			$this->stored = $value;
			$this->writes++;
			return true;
		});
	}

	protected function tearDown(): void {
		unset($_SERVER['SERVER_ADDR']);
		parent::tearDown();
	}

	public function testANewAddressIsStoredOnceAndKnownWithoutAWebRequest(): void {
		$servers = new ServerAddresses(new HotState($this->appConfig));
		$_SERVER['SERVER_ADDR'] = '192.0.2.10';
		$servers->observe();
		$servers->observe();
		$this->assertSame(1, $this->writes, 'Written only when it is new');
		unset($_SERVER['SERVER_ADDR']);
		$this->assertTrue($servers->contains(SourceKey::fromIp('192.0.2.10')));
		$this->assertFalse($servers->contains(SourceKey::fromIp('192.0.2.11')));
	}

	public function testEveryWebServerAddsItsOwnAndTheLatestAreKept(): void {
		$servers = new ServerAddresses(new HotState($this->appConfig));
		for ($i = 1; $i <= ServerAddresses::MAX_REMEMBERED + 2; $i++) {
			$_SERVER['SERVER_ADDR'] = '2001:db8::' . dechex($i);
			$servers->observe();
		}
		$this->assertCount(ServerAddresses::MAX_REMEMBERED, $this->stored);
		$this->assertSame('2001:db8::12', $this->stored[0]);
		unset($_SERVER['SERVER_ADDR']);
		$this->assertFalse($servers->contains(SourceKey::fromIp('2001:db8::1')), 'The oldest is forgotten');
	}

	public function testTheAddressOfTheRequestCountsBeforeItIsStored(): void {
		$_SERVER['SERVER_ADDR'] = '192.0.2.10';
		$servers = new ServerAddresses(new HotState($this->appConfig));
		$this->assertTrue($servers->contains(SourceKey::fromIp('192.0.2.10')));
		$this->assertSame(0, $this->writes);
	}

	public function testWithoutAWebRequestNothingIsStored(): void {
		(new ServerAddresses(new HotState($this->appConfig)))->observe();
		$this->assertSame(0, $this->writes);
	}
}
