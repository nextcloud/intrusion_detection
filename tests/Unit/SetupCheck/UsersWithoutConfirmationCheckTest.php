<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\SetupCheck;

use OCA\IntrusionDetection\Admin\SetupProblems;
use OCA\IntrusionDetection\Confirm\ConfirmationCoverage;
use OCA\IntrusionDetection\Notification\AdminLinks;
use OCA\IntrusionDetection\SetupCheck\UsersWithoutConfirmationCheck;
use OCP\L10N\IFactory;
use OCP\Server;
use OCP\SetupCheck\SetupResult;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class UsersWithoutConfirmationCheckTest extends TestCase {
	/**
	 * @return array<string, array{int, int, string}>
	 */
	public static function counts(): array {
		return [
			'everybody can confirm' => [0, 500, SetupResult::SUCCESS],
			'a few cannot' => [3, 500, SetupResult::INFO],
			'exactly a tenth' => [50, 500, SetupResult::INFO],
			'more than a tenth' => [51, 500, SetupResult::WARNING],
			'a small server' => [2, 3, SetupResult::WARNING],
		];
	}

	#[DataProvider('counts')]
	public function testTheLevelFollowsTheShareOfActiveAccounts(int $without, int $active, string $severity): void {
		$coverage = $this->createMock(ConfirmationCoverage::class);
		$coverage->method('users')->willReturn(['withoutMethod' => $without, 'active' => $active]);
		$links = $this->createMock(AdminLinks::class);
		$links->method('adminPage')->willReturn('https://cloud.example.com/settings/admin/intrusion_detection');
		$result = (new UsersWithoutConfirmationCheck(Server::get(IFactory::class)->get('intrusion_detection', 'en'), $links, $coverage))->run();
		$this->assertSame($severity, $result->getSeverity());
		if ($without > 0) {
			$this->assertStringContainsString($without . ' of ' . $active . ' active accounts', (string)$result->getDescription());
			$this->assertSame('https://cloud.example.com/settings/admin/intrusion_detection#confirmation', $result->getLinkToDoc());
		}
	}

	public function testItIsShownUnderTheStatusBanner(): void {
		$this->assertContains(UsersWithoutConfirmationCheck::class, SetupProblems::CHECKS);
	}
}
