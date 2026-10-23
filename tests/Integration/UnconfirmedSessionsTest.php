<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Confirm\Db\StepUpSessionMapper;
use OCA\IntrusionDetection\Confirm\UnconfirmedSessions;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\State\HotState;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IConfig;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;

/**
 * A session whose login was never confirmed is recognised when it comes
 * back, whatever happened to the instance secret meanwhile: otherwise a
 * new secret would let every waiting login resume unconfirmed.
 */
#[Group('DB')]
class UnconfirmedSessionsTest extends IntegrationTestCase {
	private const SESSION_ID = 'a-waiting-login-session-id-0123456789abcdef';

	private string $secret = 'the-first-instance-secret-0123456789abcdef';

	protected function tearDown(): void {
		$this->sessions()->forget(self::SESSION_ID);
		parent::tearDown();
	}

	public function testAWaitingLoginIsRecognisedAfterTheSecretChanged(): void {
		$this->sessions()->remember(self::SESSION_ID, 'alice');
		$this->assertSame('alice', $this->sessions()->accountOf(self::SESSION_ID));

		$this->secret = 'a-new-instance-secret-after-rotation-fedcba9876543210';

		$this->assertSame('alice', $this->sessions()->accountOf(self::SESSION_ID), 'It must not come back unconfirmed');
		$this->assertNull($this->sessions()->accountOf('another-session-id-0123456789abcdef'));
	}

	private function sessions(): UnconfirmedSessions {
		$config = $this->createMock(IConfig::class);
		$config->method('getSystemValueString')->willReturnCallback(fn (string $key, string $default = ''): string => $key === 'secret' ? $this->secret : $default);
		return new UnconfirmedSessions(
			Server::get(StepUpSessionMapper::class),
			new Fingerprinter($config, Server::get(ITimeFactory::class)),
			Server::get(IConfig::class),
			Server::get(ITimeFactory::class),
			Server::get(LoggerInterface::class),
			Server::get(HotState::class),
		);
	}
}
