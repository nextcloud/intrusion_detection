<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Command\Status;
use OCA\IntrusionDetection\Guard\AddressGuard;
use OCA\IntrusionDetection\SetupCheck\GuardsDisabledCheck;
use OCP\IConfig;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * The emergency switch that turns every request guard off shows in the
 * status and on the admin page while it is set.
 */
#[Group('DB')]
class GuardsDisabledTest extends IntegrationTestCase {
	protected function tearDown(): void {
		Server::get(IConfig::class)->deleteSystemValue(AddressGuard::DISABLE_SWITCH);
		parent::tearDown();
	}

	public function testTheSwitchShowsInTheStatusAndOnTheAdminPage(): void {
		$l = Server::get(IFactory::class)->get(Application::APP_ID, 'en');
		$check = Server::get(GuardsDisabledCheck::class);
		$status = new CommandTester(Server::get(Status::class));
		$this->assertNull($check->finding($l));
		$status->execute(['--output' => 'json']);
		$this->assertSame('on', json_decode($status->getDisplay(), true)['guards']);

		Server::get(IConfig::class)->setSystemValue(AddressGuard::DISABLE_SWITCH, true);
		$this->assertSame('guards_disabled', $check->finding($l)?->id);
		$status->execute(['--output' => 'json']);
		$this->assertSame('off', json_decode($status->getDisplay(), true)['guards']);
		$status->execute([]);
		$this->assertStringContainsString('Request guards off', $status->getDisplay());
	}
}
