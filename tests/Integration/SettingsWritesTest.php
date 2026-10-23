<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Admin\SettingsTransfer;
use OCA\IntrusionDetection\AdminChange\Approvers;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffing\CredentialStuffing;
use OCA\IntrusionDetection\Check\Checks\ReservedName\ReservedName;
use OCA\IntrusionDetection\Command\Checks\Set;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Definition\InvalidParamException;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Event\SettingChangedEvent;
use OCA\IntrusionDetection\State\AppState;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IUserManager;
use OCP\Log\Audit\CriticalActionPerformedEvent;
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

	/** @var list<string> */
	private array $events = [];
	private \Closure $listener;

	protected function setUp(): void {
		parent::setUp();
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
			$this->settingsEditor()->updateCheck(ReservedName::ID, Mode::Observe, ['names' => [self::USER]], [ResponseType::NotifyAdmin]);
			$this->fail('An existing account cannot be reserved');
		} catch (InvalidParamException $e) {
			$this->assertSame('existing_user', $e->reason);
		}
		$this->assertSame(Mode::Protect, $this->checkSettings()->configuredMode(ReservedName::ID), 'The mode was not saved either');
		$this->assertSame([ResponseType::Ban], $this->checkSettings()->responses(ReservedName::ID));
		$this->assertSame([], $this->events);
	}

	public function testAnAdministratorsCheckChangeIsParsedValidatedAndAuditedOnce(): void {
		$audited = [];
		$listener = static function (CriticalActionPerformedEvent $event) use (&$audited): void {
			$audited[] = [$event->getLogMessage(), $event->getParameters()];
		};
		$dispatcher = Server::get(IEventDispatcher::class);
		$dispatcher->addListener(CriticalActionPerformedEvent::class, $listener);
		try {
			$editor = $this->settingsEditor();
			$changes = $editor->changeCheck(CredentialStuffing::ID, 'observe', ['notify_admin'], ['window' => '20m', 'min_failures' => 25], 'occ');
			$this->assertSame(['mode' => 'observe', 'params' => ['window' => 1200, 'min_failures' => 25], 'responses' => ['notify_admin']], $changes);
			$this->assertSame([], $editor->changeCheck(CredentialStuffing::ID, null, null, ['min_failures' => '25'], 'occ'), 'Nothing changed, nothing audited');
			foreach ([['everything', null, []], [null, ['kill_everything'], []], [null, null, ['nope' => 1]], [null, null, ['min_failures' => 1]]] as [$mode, $responses, $params]) {
				try {
					$editor->changeCheck(CredentialStuffing::ID, $mode, $responses, $params, 'occ');
					$this->fail('Refused values were saved');
				} catch (InvalidParamException) {
				}
			}
			$editor->resetCheck(CredentialStuffing::ID, 'occ');
			$editor->resetCheck(CredentialStuffing::ID);
		} finally {
			$dispatcher->removeListener(CriticalActionPerformedEvent::class, $listener);
		}
		$this->assertSame([
			['Intrusion detection: check %s changed by %s: %s', ['check' => CredentialStuffing::ID, 'actor' => 'occ', 'change' => json_encode($changes)]],
			['Intrusion detection: check %s reset to defaults by %s', ['check' => CredentialStuffing::ID, 'actor' => 'occ']],
		], $audited, 'A reset as part of a larger change is audited by that change');
	}

	public function testACheckChangeReportsOnlyWhatChanged(): void {
		$changes = $this->settingsEditor()->updateCheck(CredentialStuffing::ID, Mode::Protect, ['window' => 600, 'min_failures' => 25], null);
		$this->assertSame(['params' => ['min_failures' => 25]], $changes, 'The mode and the window were already so');
		$this->assertSame(['check_credential_stuffing_min_failures'], $this->events);
		$this->assertSame([], $this->settingsEditor()->updateCheck(CredentialStuffing::ID, null, ['min_failures' => 25], null));
	}

	public function testAGlobalChangeWithOneRefusedValueSavesNothing(): void {
		$approvers = $this->createMock(Approvers::class);
		$approvers->method('count')->willReturn(1);
		$this->overwriteService(Approvers::class, $approvers);
		try {
			$this->settingsEditor()->updateGlobals([GlobalSettings::BAN_DURATION_1 => 7200, GlobalSettings::ADMIN_CHANGE_REQUIRE_APPROVAL => true]);
			$this->fail('One administrator cannot switch approval on');
		} catch (InvalidParamException $e) {
			$this->assertSame('too_few_admins', $e->reason);
		} finally {
			$this->restoreService(Approvers::class);
		}
		$this->assertSame(14400, $this->appSettings()->banDurations()[1]);
		$this->assertSame([], $this->events);
	}

	public function testInternalStateIsNoGlobalChange(): void {
		$this->expectException(InvalidParamException::class);
		$this->settingsEditor()->updateGlobals([AppState::INSTALLED_AT => 2]);
	}

	public function testOccSavesNothingWhenOneValueIsRefused(): void {
		$output = new BufferedOutput();
		$code = Server::get(Set::class)->run(new ArrayInput(['check' => ReservedName::ID, '--mode' => 'observe', '--param' => ['names=' . self::USER]]), $output);
		$this->assertSame(Set::INVALID, $code);
		$this->assertSame(Mode::Protect, $this->checkSettings()->configuredMode(ReservedName::ID));

		$code = Server::get(Set::class)->run(new ArrayInput(['check' => CredentialStuffing::ID, '--mode' => 'protect']), $output);
		$this->assertSame(Set::SUCCESS, $code);
		$this->assertStringContainsString('Nothing changed.', $output->fetch());
	}

	public function testResettingEverythingSendsTheEvents(): void {
		$this->settingsEditor()->setGlobal(GlobalSettings::BAN_DURATION_1, 7200);
		$this->settingsEditor()->setParam(CredentialStuffing::ID, 'window', 900);
		$this->events = [];

		Server::get(SettingsTransfer::class)->resetAll('test');

		$this->assertSame(14400, $this->appSettings()->banDurations()[1]);
		// The test case switches the admin change check and the risk score off; the reset switches them on again.
		$this->assertEqualsCanonicalizing(
			[GlobalSettings::BAN_DURATION_1, 'check_credential_stuffing_window', 'check_admin_change_mode', GlobalSettings::RISK_ENABLED],
			$this->events,
			'One event for every setting that changed, and only for those',
		);
	}
}
