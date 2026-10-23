<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Login;

use OC\Session\Memory;
use OCA\IntrusionDetection\Login\CoreSession;
use OCA\IntrusionDetection\Login\SessionMarkers;
use OCA\IntrusionDetection\Login\SessionTokenLinker;
use Psr\Log\LoggerInterface;
use Test\TestCase;

/**
 * A marker a login left for its session token is linked once, for its own
 * account only, and stays when linking fails.
 */
class SessionTokenLinkerTest extends TestCase {
	private SessionMarkers $markers;
	private ?int $tokenId = 42;

	protected function setUp(): void {
		parent::setUp();
		$this->markers = new SessionMarkers(new Memory(), $this->createMock(LoggerInterface::class));
	}

	public function testTheMarkerIsLinkedOnceAndGoes(): void {
		$this->markers->set(SessionMarkers::LOGIN_HISTORY, ['uid' => 'alice', 'id' => 7]);
		$links = [];
		$link = static function (array $marker, int $tokenId) use (&$links): void {
			$links[] = [$marker['id'], $tokenId];
		};
		$this->linker()->link(SessionMarkers::LOGIN_HISTORY, 'alice', $link);
		$this->linker()->link(SessionMarkers::LOGIN_HISTORY, 'alice', $link);
		$this->assertSame([[7, 42]], $links);
		$this->assertNull($this->markers->get(SessionMarkers::LOGIN_HISTORY));
	}

	public function testAMarkerOfAnotherAccountOrWithoutATokenGoesUnlinked(): void {
		$never = function (): void {
			$this->fail('not linked');
		};
		$this->markers->set(SessionMarkers::LOGIN_DETECTIONS, ['uid' => 'mallory', 'ids' => [1]]);
		$this->linker()->link(SessionMarkers::LOGIN_DETECTIONS, 'alice', $never);
		$this->assertNull($this->markers->get(SessionMarkers::LOGIN_DETECTIONS));

		$this->tokenId = null;
		$this->markers->set(SessionMarkers::LOGIN_DETECTIONS, ['uid' => 'alice', 'ids' => [1]]);
		$this->linker()->link(SessionMarkers::LOGIN_DETECTIONS, 'alice', $never);
		$this->assertNull($this->markers->get(SessionMarkers::LOGIN_DETECTIONS));
	}

	public function testAFailedLinkKeepsTheMarkerForTheNextRequest(): void {
		$this->markers->set(SessionMarkers::LOGIN_HISTORY, ['uid' => 'alice', 'id' => 7]);
		try {
			$this->linker()->link(SessionMarkers::LOGIN_HISTORY, 'alice', static function (): void {
				throw new \RuntimeException('database gone');
			});
			$this->fail('The error reaches the caller');
		} catch (\RuntimeException) {
		}
		$this->assertNotNull($this->markers->get(SessionMarkers::LOGIN_HISTORY));
	}

	private function linker(): SessionTokenLinker {
		$coreSession = $this->createMock(CoreSession::class);
		$coreSession->method('tokenId')->willReturnCallback(fn (): ?int => $this->tokenId);
		return new SessionTokenLinker($this->markers, $coreSession);
	}
}
