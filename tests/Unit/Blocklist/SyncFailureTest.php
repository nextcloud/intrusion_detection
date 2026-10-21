<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Blocklist;

use OCA\IntrusionDetection\Blocklist\SyncFailure;
use OCP\IL10N;
use OCP\L10N\IFactory;
use OCP\Server;
use Test\TestCase;

class SyncFailureTest extends TestCase {
	private const URL = 'https://lists.example.org/drop.txt';

	private IL10N $l;

	protected function setUp(): void {
		parent::setUp();
		$this->l = Server::get(IFactory::class)->get('intrusion_detection', 'en');
	}

	public function testAnHttpFailureNamesTheServerAndTheStatus(): void {
		$this->assertSame('lists.example.org answered with HTTP status 503', SyncFailure::describe(SyncFailure::HTTP, $this->l, self::URL, 503));
		$this->assertSame('lists.example.org answered with an error', SyncFailure::describe(SyncFailure::HTTP, $this->l, self::URL));
	}

	public function testANetworkFailureNamesTheServer(): void {
		$this->assertSame('lists.example.org could not be reached in time', SyncFailure::describe(SyncFailure::NETWORK, $this->l, self::URL));
	}

	public function testAnUnknownFailureNamesTheServerInsteadOfRepeatingItself(): void {
		$this->assertSame('the download from lists.example.org did not finish', SyncFailure::describe('gone', $this->l, self::URL));
	}

	public function testFailuresOfTheFileDoNotNeedTheServer(): void {
		$this->assertSame('the file is not in the expected format', SyncFailure::describe(SyncFailure::INVALID_FORMAT, $this->l, self::URL));
	}

	public function testWithoutAnAddressTheTextStaysGeneral(): void {
		$this->assertSame('the server answered with an error', SyncFailure::describe(SyncFailure::HTTP, $this->l, '', 503));
	}
}
