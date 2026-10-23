<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Response;

use OC\Memcache\ArrayCache;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Response\Db\ResetSuppressionMapper;
use OCA\IntrusionDetection\Response\ResetMailSuppressor;
use OCA\IntrusionDetection\Tests\Unit\Cache\FixedCaches;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Server;
use Test\TestCase;

class ResetMailSuppressorTest extends TestCase {
	public function testAnAccountWithoutSuppressionIsCachedAsZero(): void {
		$mapper = $this->createMock(ResetSuppressionMapper::class);
		$mapper->expects($this->once())->method('expiresAt')->with('alice')->willReturn(0);
		$factory = new FixedCaches(new ArrayCache());
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturn(1_800_000_000);
		$suppressor = new ResetMailSuppressor($mapper, $time, $factory, Server::get(Fingerprinter::class));

		for ($i = 0; $i < 3; $i++) {
			$this->assertFalse($suppressor->isSuppressed('alice'));
		}
	}
}
