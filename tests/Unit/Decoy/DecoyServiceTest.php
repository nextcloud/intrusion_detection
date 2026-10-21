<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Decoy;

use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Db\DecoyMapper;
use OCA\IntrusionDetection\Decoy\DecoyFormat;
use OCA\IntrusionDetection\Decoy\DecoyService;
use OCA\IntrusionDetection\Traps\AccountNames;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Security\ISecureRandom;
use OCP\Server;
use Test\TestCase;

class DecoyServiceTest extends TestCase {
	public function testWithoutDecoysAFailedLoginCostsNoQuery(): void {
		$settings = $this->createMock(Settings::class);
		$settings->method('getInt')->with(GlobalSettings::DECOY_COUNT)->willReturn(0);
		$mapper = $this->createMock(DecoyMapper::class);
		$mapper->expects($this->never())->method('findMatching');
		$fingerprinter = $this->createMock(Fingerprinter::class);
		$fingerprinter->expects($this->never())->method('decoy');
		$service = new DecoyService($mapper, $fingerprinter, $this->createMock(ISecureRandom::class), $this->createMock(AccountNames::class), $settings, $this->createMock(AuditLogger::class), $this->createMock(ITimeFactory::class));
		$this->assertNull($service->match('some password', 'alice'));
	}

	public function testGeneratedSecretsAreRandomAndShapedLikeCoresCredentials(): void {
		$random = Server::get(ISecureRandom::class);
		$seen = [];
		for ($i = 0; $i < 20; $i++) {
			$appPassword = DecoyFormat::AppPassword->generate($random);
			$this->assertSame(29, strlen($appPassword));
			$this->assertSame(4, substr_count($appPassword, '-'));
			$this->assertSame('', trim($appPassword, '-' . ISecureRandom::CHAR_HUMAN_READABLE));
			$token = DecoyFormat::Token->generate($random);
			$this->assertSame(72, strlen($token));
			$this->assertTrue(ctype_alnum($token));
			$seen[$appPassword] = true;
			$seen[$token] = true;
		}
		$this->assertCount(40, $seen);
	}
}
