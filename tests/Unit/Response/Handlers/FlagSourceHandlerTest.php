<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Response\Handlers;

use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\Response\Handlers\FlagSourceHandler;
use OCA\IntrusionDetection\Response\ResponseContext;
use OCA\IntrusionDetection\Response\ResponseOutcome;
use OCP\L10N\IFactory;
use OCP\Server;
use Test\TestCase;

class FlagSourceHandlerTest extends TestCase {
	public function testAnAddressThatIsNotFlaggedIsHeldBackAndSaysWhy(): void {
		$flags = $this->createMock(FlaggedSources::class);
		$flags->method('flagSource')->willReturn(null);
		$handler = new FlagSourceHandler($flags);

		$outcome = $handler->apply($this->context());
		$this->assertFalse($outcome->enforced);
		$this->assertSame(ResponseOutcome::NOTE_HELD_BACK, $outcome->note);

		$action = ['type' => 'flag_source', 'enforced' => false, 'note' => $outcome->note, 'ref' => $outcome->ref];
		$this->assertSame(
			['Logins from this address do not need extra confirmation: many people log in from it, or it may be a reverse proxy.'],
			$handler->describeAction($action, Server::get(IFactory::class)->get('intrusion_detection', 'en'), $this->createMock(DateFormatter::class)),
		);
	}

	public function testAFlaggedAddressSaysUntilWhen(): void {
		$flags = $this->createMock(FlaggedSources::class);
		$flags->method('flagSource')->willReturn(1000);
		$handler = new FlagSourceHandler($flags);

		$outcome = $handler->apply($this->context());
		$this->assertTrue($outcome->enforced);
		$this->assertSame(['sources' => 1, 'until' => 1000], $outcome->ref);
	}

	private function context(): ResponseContext {
		$detection = new Detection();
		$detection->generateId();
		$draft = new DetectionDraft(checkId: 'blocklist_match', source: SourceKey::fromIp('198.51.100.7'));
		return new ResponseContext($draft, $detection, Server::get(CheckRegistry::class)->get($draft->checkId), true);
	}
}
