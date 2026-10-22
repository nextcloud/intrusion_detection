<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\SetupCheck;

use OCA\IntrusionDetection\Admin\SetupProblems;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Notification\AdminLinks;
use OCA\IntrusionDetection\SetupCheck\AdminNetworksCheck;
use OCP\L10N\IFactory;
use OCP\Server;
use OCP\SetupCheck\SetupResult;
use Test\TestCase;

class AdminNetworksCheckTest extends TestCase {
	public function testTheSwitchWithoutTrustedNetworksIsAWarning(): void {
		$result = $this->check(true, []);
		$this->assertSame(SetupResult::WARNING, $result->getSeverity());
		$this->assertStringContainsString('there are no trusted networks yet, so every administrator login from anywhere needs confirmation', (string)$result->getDescription());
		$this->assertStringEndsWith('#settings-confirmation', (string)$result->getLinkToDoc());
	}

	public function testTheSwitchWithTrustedNetworksIsFine(): void {
		$this->assertSame(SetupResult::SUCCESS, $this->check(true, ['192.0.2.0/24'])->getSeverity());
	}

	public function testWithTheSwitchOffAnEmptyListIsFine(): void {
		$result = $this->check(false, []);
		$this->assertSame(SetupResult::SUCCESS, $result->getSeverity());
		$this->assertSame('Administrators may log in from any network.', $result->getDescription());
	}

	public function testItIsShownUnderTheStatusBanner(): void {
		$this->assertContains(AdminNetworksCheck::class, SetupProblems::CHECKS);
	}

	/**
	 * @param list<string> $networks
	 */
	private function check(bool $on, array $networks): SetupResult {
		$settings = $this->createMock(Settings::class);
		$settings->method('getBool')->willReturnCallback(static fn (string $name): bool => $name === GlobalSettings::ADMIN_TRUSTED_NETWORKS_ONLY && $on);
		$settings->method('global')->willReturnCallback(static fn (string $name): array => $name === GlobalSettings::RISKY_NETWORK_OFFICE_NETWORKS ? $networks : []);
		$links = $this->createMock(AdminLinks::class);
		$links->method('adminPage')->willReturn('https://cloud.example.com/settings/admin/intrusion_detection');
		return (new AdminNetworksCheck(Server::get(IFactory::class)->get('intrusion_detection', 'en'), $links, $settings))->run();
	}
}
