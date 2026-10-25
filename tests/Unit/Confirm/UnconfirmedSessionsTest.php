<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Confirm;

use OCA\IntrusionDetection\Confirm\Db\StepUpSessionMapper;
use OCA\IntrusionDetection\Confirm\UnconfirmedSessions;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\State\HotState;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IConfig;
use Psr\Log\NullLogger;
use Test\TestCase;

class UnconfirmedSessionsTest extends TestCase {
	private const NOW = 1792625400;
	private const LIFETIME = UnconfirmedSessions::DEFAULT_REMEMBER_LIFETIME + 3600;

	private int $now = self::NOW;
	private int $until = 0;
	private int $writes = 0;

	public function testTheEndOfTheLastSessionIsWrittenOnceADay(): void {
		$sessions = $this->sessions();
		$sessions->remember('session-1', 'alice');
		$this->assertSame(1, $this->writes);
		$this->assertSame(self::NOW + self::LIFETIME + 86400, $this->until, 'A day ahead of the session');

		for ($i = 2; $i <= 60; $i++) {
			$this->now += 1700;
			$sessions->remember('session-' . $i, 'alice');
			$this->assertGreaterThanOrEqual($this->now + self::LIFETIME, $this->until, 'Every remembered session is covered');
		}
		$this->assertSame(2, $this->writes, '60 logins over 28 hours write it twice');
		$this->assertTrue($sessions->mayExist());
	}

	private function sessions(): UnconfirmedSessions {
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturnCallback(fn (): int => $this->now);
		$config = $this->createMock(IConfig::class);
		$config->method('getSystemValueInt')->willReturnCallback(static fn (string $key, int $default): int => $default);
		$config->method('getSystemValueString')->willReturn('a-test-secret');
		$hotState = $this->createMock(HotState::class);
		$hotState->method('stepUpSessionsUntil')->willReturnCallback(fn (): int => $this->until);
		$hotState->method('setStepUpSessionsUntil')->willReturnCallback(function (int $until): void {
			$this->until = $until;
			$this->writes++;
		});
		return new UnconfirmedSessions($this->createMock(StepUpSessionMapper::class), new Fingerprinter($config, $time), $config, $time, new NullLogger(), $hotState);
	}
}
