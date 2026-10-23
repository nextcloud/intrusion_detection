<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AdminChange\ApprovalException;
use OCA\IntrusionDetection\AdminChange\ApprovalService;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\AdminChange\AdminChange;
use OCA\IntrusionDetection\Command\Checks\Set;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Keys;
use OCA\IntrusionDetection\Controller\ApprovalController;
use OCA\IntrusionDetection\Controller\CheckApiController;
use OCA\IntrusionDetection\Controller\SettingsApiController;
use OCA\IntrusionDetection\Db\Approval;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\Severity;
use OCA\IntrusionDetection\Notification\Notifier;
use OCP\AppFramework\Http;
use OCP\AppFramework\IAppContainer;
use OCP\IUserSession;
use OCP\Notification\INotification;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * While a second administrator must approve new administrators, one
 * administrator alone cannot switch that off from the admin page or the
 * API: the change waits for the approval of another one. occ is not held,
 * and is reported.
 */
#[Group('DB')]
class SwitchOffApprovalTest extends AdminChangeTestCase {
	use OcsPipeline;

	private IAppContainer $container;
	private ApprovalService $approvals;

	protected function setUp(): void {
		parent::setUp();
		$this->requireApproval();
		Server::get(IUserSession::class)->setUser($this->user($this->alice));
		$this->container = (new Application())->getContainer();
		$this->approvals = Server::get(ApprovalService::class);
	}

	protected function tearDown(): void {
		Server::get(IUserSession::class)->setUser(null);
		parent::tearDown();
	}

	public function testSwitchingApprovalOffWaitsForASecondAdministrator(): void {
		$answer = $this->ocs($this->container->get(SettingsApiController::class), 'updateSettings', [[GlobalSettings::ADMIN_CHANGE_REQUIRE_APPROVAL => false, GlobalSettings::BAN_DURATION_1 => '2h']]);

		$this->assertSame(Http::STATUS_FORBIDDEN, $answer['status']);
		$this->assertSame(ApprovalException::HELD, $answer['data']['reason']);
		$this->assertTrue($this->appSettings()->adminChangeRequireApproval(), 'Nothing is saved yet');
		$this->assertSame(14400, $this->appSettings()->banDurations()[1]);

		$request = $this->pendingChange();
		$this->assertSame($this->alice, $request->getRequestedBy());
		$this->approvals->approve((int)$request->getId(), $this->carol, ApprovalService::VIA_WEB);
		$this->assertFalse($this->appSettings()->adminChangeRequireApproval(), 'Made once another administrator approved');
		$this->assertSame(7200, $this->appSettings()->banDurations()[1]);
	}

	public function testSwitchingProtectionOffWaitsForASecondAdministrator(): void {
		$answer = $this->ocs($this->container->get(SettingsApiController::class), 'updateSettings', [[GlobalSettings::ENABLED => false]]);
		$this->assertSame(Http::STATUS_FORBIDDEN, $answer['status']);
		$this->assertTrue($this->appSettings()->isEnabled());
		$this->assertNotNull($this->pendingChange());
	}

	public function testTheOtherAdministratorsAreAskedWithWhatTheChangeDoes(): void {
		$this->ocs($this->container->get(SettingsApiController::class), 'updateSettings', [[GlobalSettings::ADMIN_CHANGE_REQUIRE_APPROVAL => false]]);

		$asked = array_values(array_filter($this->notificationsWithSubject(Notifier::SUBJECT_APPROVAL_REQUESTED), fn (INotification $n): bool => $n->getUser() === $this->carol));
		$this->assertCount(1, $asked);
		$prepared = Server::get(Notifier::class)->prepare($asked[0], 'en');
		$this->assertSame($this->alice . ' asks for a change that needs your approval', $prepared->getParsedSubject());
		$this->assertStringContainsString('Stop asking a second administrator to approve new administrators.', $prepared->getParsedMessage());

		Server::get(IUserSession::class)->setUser($this->user($this->carol));
		$listed = $this->ocs($this->container->get(ApprovalController::class), 'adminGrants')['data'];
		$this->assertCount(1, $listed);
		$this->assertSame('settings', $listed[0]['kind']);
		$this->assertSame('Stop asking a second administrator to approve new administrators.', $listed[0]['change']);
		$this->assertTrue($listed[0]['canApprove']);
	}

	public function testLoweringTheAdminChangeCheckWaitsForASecondAdministrator(): void {
		$answer = $this->ocs($this->container->get(CheckApiController::class), 'updateCheck', [AdminChange::ID, Mode::Observe->value]);
		$this->assertSame(Http::STATUS_FORBIDDEN, $answer['status']);
		$this->assertSame(Mode::Protect, $this->checkSettings()->configuredMode(AdminChange::ID));

		$this->approvals->approve((int)$this->pendingChange()->getId(), $this->carol, ApprovalService::VIA_WEB);
		$this->assertSame(Mode::Observe, $this->checkSettings()->configuredMode(AdminChange::ID));
	}

	public function testResettingAllSettingsWaitsForASecondAdministrator(): void {
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::BAN_DURATION_1, 7200);
		$answer = $this->ocs($this->container->get(SettingsApiController::class), 'resetSettings');
		$this->assertSame(Http::STATUS_FORBIDDEN, $answer['status']);
		$this->assertTrue($this->appSettings()->adminChangeRequireApproval());
		$this->assertSame(7200, $this->appSettings()->banDurations()[1]);

		$this->approvals->approve((int)$this->pendingChange()->getId(), $this->carol, ApprovalService::VIA_WEB);
		$this->assertFalse($this->appSettings()->adminChangeRequireApproval());
		$this->assertSame(14400, $this->appSettings()->banDurations()[1]);
	}

	public function testTheAdministratorWhoAskedCannotApprove(): void {
		$this->ocs($this->container->get(SettingsApiController::class), 'updateSettings', [[GlobalSettings::ADMIN_CHANGE_REQUIRE_APPROVAL => false]]);
		$this->expectException(ApprovalException::class);
		$this->approvals->approve((int)$this->pendingChange()->getId(), $this->alice, ApprovalService::VIA_WEB);
	}

	public function testOtherChangesAreNotHeld(): void {
		$answer = $this->ocs($this->container->get(SettingsApiController::class), 'updateSettings', [[GlobalSettings::BAN_DURATION_1 => '2h']]);
		$this->assertSame(Http::STATUS_OK, $answer['status']);
		$answer = $this->ocs($this->container->get(CheckApiController::class), 'updateCheck', [AdminChange::ID, Mode::Protect->value]);
		$this->assertSame(Http::STATUS_OK, $answer['status']);
		$answer = $this->ocs($this->container->get(CheckApiController::class), 'updateCheck', ['credential_stuffing', Mode::Off->value]);
		$this->assertSame(Http::STATUS_OK, $answer['status']);
		$this->assertSame([], $this->approvals->list(true, 10, Approval::KIND_SETTINGS));
	}

	public function testWithoutApprovalNothingIsHeld(): void {
		$this->requireApproval(false);
		$answer = $this->ocs($this->container->get(SettingsApiController::class), 'updateSettings', [[GlobalSettings::ENABLED => false]]);
		$this->assertSame(Http::STATUS_OK, $answer['status']);
		$this->assertFalse($this->appSettings()->isEnabled());
	}

	public function testOccIsNotHeldButReported(): void {
		$tester = new CommandTester(Server::get(Set::class));
		$this->assertSame(0, $tester->execute(['check' => AdminChange::ID, '--mode' => Mode::Off->value]));
		$this->assertSame(Mode::Off->value, $this->appConfig->getValueString(Application::APP_ID, Keys::mode(AdminChange::ID)));
		$reported = array_filter($this->adminChanges(), fn ($d): bool => ($this->facts($d)['setting'] ?? '') === 'app:intrusion_detection:' . Keys::mode(AdminChange::ID));
		$this->assertCount(1, $reported);
		$this->assertSame(Severity::High->value, array_values($reported)[0]->getSeverity());
	}

	private function pendingChange(): Approval {
		$pending = $this->approvals->list(true, 10, Approval::KIND_SETTINGS);
		$this->assertCount(1, $pending);
		return $pending[0];
	}
}
