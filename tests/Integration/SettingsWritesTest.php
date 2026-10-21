<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Admin\SettingsTransfer;
use OCA\IntrusionDetection\AdminChange\Approvers;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffing;
use OCA\IntrusionDetection\Check\Checks\ReservedName;
use OCA\IntrusionDetection\Check\InvalidParamException;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Command\Checks\Set;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Event\SettingChangedEvent;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IUserManager;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;

/**
 * Writes of several settings at once validate every value first, report
 * what really changed, and send SettingChangedEvent for every change.
 */
#[Group('DB')]
class SettingsWritesTest extends IntegrationTestCase {
	private const USER = 'ids-settings-existing';

	private Settings $settings;
	/** @var list<string> */
	private array $events = [];
	private \Closure $listener;

	protected function setUp(): void {
		parent::setUp();
		$this->settings = Server::get(Settings::class);
		$users = Server::get(IUserManager::class);
		if (!$users->userExists(self::USER)) {
			$users->createUser(self::USER, 'Ids-Test-Password-2026');
		}
		$this->listener = function (SettingChangedEvent $event): void {
			$this->events[] = $event->getKey();
		};
		Server::get(IEventDispatcher::class)->addListener(SettingChangedEvent::class, $this->listener);
	}

	protected function tearDown(): void {
		Server::get(IEventDispatcher::class)->removeListener(SettingChangedEvent::class, $this->listener);
		Server::get(IUserManager::class)->get(self::USER)?->delete();
		parent::tearDown();
	}

	public function testACheckChangeWithOneRefusedValueSavesNothing(): void {
		try {
			// The check's own validator refuses an existing account, after the mode and the responses were fine.
			$this->settings->updateCheck(ReservedName::ID, Mode::Observe, ['names' => [self::USER]], [ResponseType::NotifyAdmin]);
			$this->fail('An existing account cannot be reserved');
		} catch (InvalidParamException $e) {
			$this->assertSame('existing_user', $e->reason);
		}
		$this->assertSame(Mode::Protect, $this->settings->configuredMode(ReservedName::ID), 'The mode was not saved either');
		$this->assertSame([ResponseType::Ban], $this->settings->responses(ReservedName::ID));
		$this->assertSame([], $this->events);
	}

	public function testACheckChangeReportsOnlyWhatChanged(): void {
		$changes = $this->settings->updateCheck(CredentialStuffing::ID, Mode::Protect, ['window' => 600, 'min_failures' => 25], null);
		$this->assertSame(['params' => ['min_failures' => 25]], $changes, 'The mode and the window were already so');
		$this->assertSame(['check_credential_stuffing_min_failures'], $this->events);
		$this->assertSame([], $this->settings->updateCheck(CredentialStuffing::ID, null, ['min_failures' => 25], null));
	}

	public function testAGlobalChangeWithOneRefusedValueSavesNothing(): void {
		$approvers = $this->createMock(Approvers::class);
		$approvers->method('count')->willReturn(1);
		$this->overwriteService(Approvers::class, $approvers);
		try {
			$this->settings->updateGlobals([GlobalSettings::BAN_DURATION_1 => 7200, GlobalSettings::ADMIN_CHANGE_REQUIRE_APPROVAL => true]);
			$this->fail('One administrator cannot switch approval on');
		} catch (InvalidParamException $e) {
			$this->assertSame('too_few_admins', $e->reason);
		} finally {
			$this->restoreService(Approvers::class);
		}
		$this->assertSame(14400, $this->settings->getInt(GlobalSettings::BAN_DURATION_1));
		$this->assertSame([], $this->events);
	}

	public function testInternalStateIsNoGlobalChange(): void {
		$this->expectException(InvalidParamException::class);
		$this->settings->updateGlobals([GlobalSettings::BAN_VERSION => 2]);
	}

	public function testOccSavesNothingWhenOneValueIsRefused(): void {
		$output = new BufferedOutput();
		$code = Server::get(Set::class)->run(new ArrayInput(['check' => ReservedName::ID, '--mode' => 'observe', '--param' => ['names=' . self::USER]]), $output);
		$this->assertSame(Set::INVALID, $code);
		$this->assertSame(Mode::Protect, $this->settings->configuredMode(ReservedName::ID));

		$code = Server::get(Set::class)->run(new ArrayInput(['check' => CredentialStuffing::ID, '--mode' => 'protect']), $output);
		$this->assertSame(Set::SUCCESS, $code);
		$this->assertStringContainsString('Nothing changed.', $output->fetch());
	}

	public function testResettingEverythingSendsTheEvents(): void {
		$this->settings->setGlobal(GlobalSettings::BAN_DURATION_1, 7200);
		$this->settings->setParam(CredentialStuffing::ID, 'window', 900);
		$this->events = [];

		Server::get(SettingsTransfer::class)->resetAll();

		$this->assertSame(14400, $this->settings->getInt(GlobalSettings::BAN_DURATION_1));
		// The test case switches the admin change check and the risk score off; the reset switches them on again.
		$this->assertEqualsCanonicalizing(
			[GlobalSettings::BAN_DURATION_1, 'check_credential_stuffing_window', 'check_admin_change_mode', GlobalSettings::RISK_ENABLED],
			$this->events,
			'One event for every setting that changed, and only for those',
		);
	}
}
