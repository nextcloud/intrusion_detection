<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AdminChange\ActorResolver;
use OCA\IntrusionDetection\AdminChange\AdminGrantGate;
use OCA\IntrusionDetection\AdminChange\ApprovalException;
use OCA\IntrusionDetection\AdminChange\ApprovalService;
use OCA\IntrusionDetection\AdminChange\Approvers;
use OCA\IntrusionDetection\AdminChange\GrantPermit;
use OCA\IntrusionDetection\AdminChange\HeldChanges;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\Checks\AdminChange\AdminChange;
use OCA\IntrusionDetection\Check\Checks\AdminChange\AdminChangeFacts;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Db\Approval;
use OCA\IntrusionDetection\Db\ApprovalMapper;
use OCA\IntrusionDetection\Definition\InvalidParamException;
use OCA\IntrusionDetection\Definition\Severity;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Notification\AdminAlerts;
use OCA\IntrusionDetection\Notification\AdminLinks;
use OCA\IntrusionDetection\Notification\Notifier;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Group\Backend\ABackend;
use OCP\Group\Backend\INamedBackend;
use OCP\Group\Events\UserAddedEvent;
use OCP\GroupInterface;
use OCP\IGroup;
use OCP\IGroupManager;
use OCP\IUserManager;
use OCP\L10N\IFactory;
use OCP\Notification\AlreadyProcessedException;
use OCP\Notification\IManager as INotificationManager;
use OCP\Notification\INotification;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;

/**
 * Four-eyes approval of new administrators (concept section 10.15, verify
 * item 11): the addition is taken back and becomes a request that another
 * administrator decides.
 */
#[Group('DB')]
class ApprovalFlowTest extends AdminChangeTestCase {
	private ApprovalService $approvals;

	protected function setUp(): void {
		parent::setUp();
		$this->approvals = Server::get(ApprovalService::class);
		$this->requireApproval();
	}

	public function testAWebAdditionIsTakenBackAndBecomesARequest(): void {
		$this->act($this->alice);
		$this->addAsWeb('admin', $this->bob);

		$this->assertFalse($this->inGroup('admin', $this->bob), 'The new member was taken out again');
		[$approval] = $this->approvals->list(true);
		$this->assertSame($this->bob, $approval->getSubjectUid());
		$this->assertSame($this->alice, $approval->getRequestedBy());
		$this->assertSame('admin', $approval->getGroupId());
		$this->assertSame(Approval::STATUS_PENDING, $approval->getStatus());
		$this->assertSame(604800, $approval->getExpiresAt() - $approval->getCreatedAt());

		[$detection] = $this->adminChanges();
		$facts = $this->facts($detection);
		$this->assertSame(AdminChange::KIND_GRANT_REQUESTED, $facts['kind']);
		$this->assertSame(Severity::High->value, $detection->getSeverity());
		$this->assertTrue($facts['reverted']);
		$this->assertSame($approval->getId(), $facts['approval']);
		$this->assertSame([], $this->notificationsWithSubject(AdminAlerts::SUBJECT), 'The approval request is the only notification');
		$this->assertSame([], $detection->getActionList(), 'No response runs for a held-back grant');

		$asked = $this->notificationsWithSubject(Notifier::SUBJECT_APPROVAL_REQUESTED);
		$askedUsers = array_map(static fn (INotification $n): string => $n->getUser(), $asked);
		$this->assertContains($this->carol, $askedUsers);
		$this->assertNotContains($this->alice, $askedUsers, 'The one who asked is not asked to approve');
		$this->assertNotContains($this->bob, $askedUsers);
		$this->assertSame([$this->alice], array_map(static fn (INotification $n): string => $n->getUser(), $this->notificationsWithSubject(Notifier::SUBJECT_APPROVAL_PENDING)));

		$prepared = Server::get(Notifier::class)->prepare($asked[0], 'en');
		$this->assertSame($this->alice . ' asks to make ' . $this->bob . ' an administrator', $prepared->getParsedSubject());
		$this->assertReviewedOnTheAdminPage($prepared, (int)$approval->getId());
		$this->assertSame(['WEB'], array_map(static fn ($a): string => $a->getRequestType(), $asked[0]->getActions()), 'Only a link is stored');
	}

	public function testANotificationStoredWithApproveAndRejectActionsOpensTheAdminPage(): void {
		$this->act($this->alice);
		$this->addAsWeb('admin', $this->bob);
		[$approval] = $this->approvals->list(true);
		$id = (int)$approval->getId();

		$stored = Server::get(INotificationManager::class)->createNotification();
		$stored->setApp(Application::APP_ID)
			->setUser($this->carol)
			->setDateTime(new \DateTime())
			->setObject(ApprovalService::OBJECT_TYPE, (string)$id)
			->setSubject(Notifier::SUBJECT_APPROVAL_REQUESTED, ['approval' => $id]);
		foreach (['approve', 'reject'] as $label) {
			$action = $stored->createAction();
			$action->setLabel($label)->setLink('https://cloud.example.com/ocs/v2.php/apps/intrusion_detection/api/v1/approvals/' . $id . '/' . $label, 'POST');
			$stored->addAction($action);
		}
		$this->assertReviewedOnTheAdminPage(Server::get(Notifier::class)->prepare($stored, 'en'), $id);
	}

	public function testAnAdditionToAGroupWithDelegatedAdminSettingsWaitsToo(): void {
		$this->delegate('ids-ac-delegates');
		$this->act($this->alice);
		$this->addAsWeb('ids-ac-delegates', $this->bob);

		$this->assertFalse($this->inGroup('ids-ac-delegates', $this->bob), 'Taken out again');
		[$approval] = $this->approvals->list(true);
		$this->assertSame('ids-ac-delegates', $approval->getGroupId());
		[$detection] = $this->adminChanges();
		$this->assertSame(AdminChange::KIND_GRANT_REQUESTED, $this->facts($detection)['kind']);
		$this->assertSame(['Users'], $this->facts($detection)['delegated']);
		$this->assertSame('Approval needed: ' . $this->bob . ' to join "ids-ac-delegates", which has administration rights', Server::get(AdminAlerts::class)->headline($detection, Server::get(IFactory::class)->get(Application::APP_ID, 'en')));

		$asked = array_values(array_filter($this->notificationsWithSubject(Notifier::SUBJECT_APPROVAL_REQUESTED), fn (INotification $n): bool => $n->getUser() === $this->carol));
		$this->assertSame($this->alice . ' asks to add ' . $this->bob . ' to the group "ids-ac-delegates", which has administration rights', Server::get(Notifier::class)->prepare($asked[0], 'en')->getParsedSubject());

		$this->approvals->approve((int)$approval->getId(), $this->carol, ApprovalService::VIA_WEB);
		$this->assertTrue($this->inGroup('ids-ac-delegates', $this->bob));
	}

	public function testOrdinaryGroupsDoNotWait(): void {
		$this->createGroup('ids-ac-plain');
		$this->act($this->alice);
		$this->addAsWeb('ids-ac-plain', $this->bob);
		$this->assertTrue($this->inGroup('ids-ac-plain', $this->bob));
		$this->assertSame([], $this->approvals->list(true));
	}

	public function testAnotherAddOfTheSameAccountReusesTheRequest(): void {
		$this->act($this->alice);
		$this->addAsWeb('admin', $this->bob);
		$this->addAsWeb('admin', $this->bob);
		$this->assertCount(1, $this->approvals->list(true));
	}

	public function testTooManyPendingRequestsAreNotStoredButStillHeldBack(): void {
		$mapper = Server::get(ApprovalMapper::class);
		for ($i = 0; $i < ApprovalService::MAX_PENDING; $i++) {
			$approval = new Approval();
			$approval->setKind(Approval::KIND_ADMIN_GRANT);
			$approval->setSubjectUid('ids-ac-filler-' . $i);
			$approval->setRequestedBy($this->alice);
			$approval->setGroupId('admin');
			$approval->setStatus(Approval::STATUS_PENDING);
			$approval->setCreatedAt(time());
			$approval->setExpiresAt(time() + 3600);
			$mapper->insert($approval);
		}
		$this->act($this->alice);
		$this->addAsWeb('admin', $this->bob);
		$this->assertFalse($this->inGroup('admin', $this->bob));
		$this->assertNull($mapper->findPending(Approval::KIND_ADMIN_GRANT, $this->bob, 'admin'));
		[$detection] = $this->adminChanges();
		$this->assertNull(AdminChangeFacts::fromArray($this->facts($detection))->approval, 'No request was stored');
		$this->assertNotSame([], $this->notificationsWithSubject(AdminAlerts::SUBJECT), 'Without a request the administrators are alerted');
	}

	public function testTheRequesterTheSubjectAndNonAdminsCannotApprove(): void {
		$id = $this->requestBob();
		foreach ([[$this->alice, ApprovalException::REQUESTER], [$this->bob, ApprovalException::SUBJECT], [$this->dave, ApprovalException::NOT_ADMIN], ['nobody-' . $this->bob, ApprovalException::NOT_ADMIN]] as [$decider, $reason]) {
			try {
				$this->approvals->approve($id, $decider, ApprovalService::VIA_WEB);
				$this->fail($decider . ' must not approve');
			} catch (ApprovalException $e) {
				$this->assertSame($reason, $e->reason);
			}
		}
		$this->assertFalse($this->inGroup('admin', $this->bob));
		$this->assertSame(Approval::STATUS_PENDING, $this->approvals->find($id)->getStatus());
	}

	public function testAnotherAdminApprovesAndTheAccountJoins(): void {
		$id = $this->requestBob();
		$approval = $this->approvals->approve($id, $this->carol, ApprovalService::VIA_WEB);

		$this->assertTrue($this->inGroup('admin', $this->bob));
		$this->assertSame(Approval::STATUS_APPROVED, $approval->getStatus());
		$this->assertSame($this->carol, $approval->getDecidedBy());

		$granted = array_values(array_filter($this->adminChanges(), fn ($d): bool => $this->facts($d)['kind'] === AdminChange::KIND_ADMIN_GRANTED));
		$this->assertCount(1, $granted, 'The approved addition is reported once');
		$facts = $this->facts($granted[0]);
		$this->assertSame($this->carol, $facts['approved_by']);
		$this->assertSame($this->alice, $facts['requested_by']);
		$this->assertSame($id, $facts['approval']);

		$decided = $this->notificationsWithSubject(Notifier::SUBJECT_APPROVAL_DECIDED);
		$this->assertSame([$this->alice], array_map(static fn (INotification $n): string => $n->getUser(), $decided));
		$this->assertSame($this->bob . ' is now an administrator', Server::get(Notifier::class)->prepare($decided[0], 'en')->getParsedSubject());

		// The open requests disappear once decided.
		$this->expectException(AlreadyProcessedException::class);
		Server::get(Notifier::class)->prepare($this->notificationsWithSubject(Notifier::SUBJECT_APPROVAL_REQUESTED)[0], 'en');
	}

	public function testAnApprovalWhoseAdditionFailsStillWaits(): void {
		$id = $this->requestBob();
		$group = $this->createMock(IGroup::class);
		$group->method('getGID')->willReturn('admin');
		$group->method('addUser')->willThrowException(new \RuntimeException('The group backend is read-only'));
		$groupManager = $this->createMock(IGroupManager::class);
		$groupManager->method('get')->willReturn($group);
		$service = new ApprovalService(
			Server::get(ApprovalMapper::class),
			Server::get(Approvers::class),
			Server::get(GrantPermit::class),
			Server::get(HeldChanges::class),
			Server::get(RemoteAddressResolver::class),
			$groupManager,
			Server::get(IUserManager::class),
			Server::get(INotificationManager::class),
			Server::get(AdminLinks::class),
			Server::get(AuditLogger::class),
			Server::get(ITimeFactory::class),
			Server::get(LoggerInterface::class),
		);
		try {
			$service->approve($id, $this->carol, ApprovalService::VIA_WEB);
			$this->fail('The addition failed');
		} catch (ApprovalException $e) {
			$this->assertSame(ApprovalException::NOT_CARRIED_OUT, $e->reason);
		}
		$approval = $this->approvals->find($id);
		$this->assertSame(Approval::STATUS_PENDING, $approval->getStatus(), 'Not marked approved while nothing happened');
		$this->assertNull($approval->getDecidedBy());
		$this->assertNull(Server::get(GrantPermit::class)->consume($this->bob, 'admin'), 'No permit is left behind');

		$this->approvals->approve($id, $this->carol, ApprovalService::VIA_WEB);
		$this->assertTrue($this->inGroup('admin', $this->bob), 'It can be approved again');
	}

	public function testAnApprovedSettingsChangeThatCannotBeMadeStillWaits(): void {
		$approval = new Approval();
		$approval->setKind(Approval::KIND_SETTINGS);
		$approval->setSubjectUid($this->alice);
		$approval->setRequestedBy($this->alice);
		$approval->setPayload(json_encode(['op' => HeldChanges::CHECK, 'check' => 'no_such_check', 'mode' => 'off']));
		$approval->setStatus(Approval::STATUS_PENDING);
		$approval->setCreatedAt(time());
		$approval->setExpiresAt(time() + 3600);
		$id = (int)Server::get(ApprovalMapper::class)->insert($approval)->getId();
		try {
			$this->approvals->approve($id, $this->carol, ApprovalService::VIA_WEB);
			$this->fail('The change cannot be made');
		} catch (ApprovalException $e) {
			$this->assertSame(ApprovalException::NOT_CARRIED_OUT, $e->reason);
		}
		$this->assertSame(Approval::STATUS_PENDING, $this->approvals->find($id)->getStatus());
	}

	public function testAnExpiredRequestCannotBeDecidedEvenInTheSameMoment(): void {
		$id = $this->requestBob();
		$this->expire($id);
		$mapper = Server::get(ApprovalMapper::class);
		$this->assertFalse($mapper->decide($id, Approval::STATUS_APPROVED, $this->carol, time()), 'The update itself checks the expiry');
		$this->assertTrue($mapper->decide($id, Approval::STATUS_EXPIRED, null, time()));
	}

	public function testWaitingLoginsCannotCrowdOutNewAdministrators(): void {
		$mapper = Server::get(ApprovalMapper::class);
		for ($i = 0; $i < ApprovalService::MAX_PENDING; $i++) {
			$approval = new Approval();
			$approval->setKind(Approval::KIND_LOGIN);
			$approval->setSubjectUid('ids-ac-filler-' . $i);
			$approval->setRequestedBy('ids-ac-filler-' . $i);
			$approval->setStatus(Approval::STATUS_PENDING);
			$approval->setCreatedAt(time());
			$approval->setExpiresAt(time() + 3600);
			$mapper->insert($approval);
		}
		$this->act($this->alice);
		$this->addAsWeb('admin', $this->bob);
		$this->assertNotNull($mapper->findPending(Approval::KIND_ADMIN_GRANT, $this->bob, 'admin'), 'Each kind has its own limit');
	}

	public function testTheApprovalCannotBeReplayed(): void {
		$id = $this->requestBob();
		$this->approvals->approve($id, $this->carol, ApprovalService::VIA_WEB);
		$this->assertNull(Server::get(GrantPermit::class)->consume($this->bob, 'admin'), 'The permit is gone after the approved addition');

		// Taken out and added again: a new request.
		$this->group('admin')->removeUser($this->user($this->bob));
		$this->act($this->alice);
		$this->addAsWeb('admin', $this->bob);
		$this->assertFalse($this->inGroup('admin', $this->bob));
		$this->assertCount(1, $this->approvals->list(true));

		try {
			$this->approvals->approve($id, $this->carol, ApprovalService::VIA_WEB);
			$this->fail('A decided request cannot be decided again');
		} catch (ApprovalException $e) {
			$this->assertSame(ApprovalException::NOT_PENDING, $e->reason);
		}
	}

	public function testAPermitForOneAccountDoesNotLetAnotherIn(): void {
		Server::get(GrantPermit::class)->allow($this->bob, 'admin');
		$this->act($this->alice);
		$this->addAsWeb('admin', $this->dave);
		$this->assertFalse($this->inGroup('admin', $this->dave));
		Server::get(GrantPermit::class)->revoke($this->bob, 'admin');
	}

	public function testARejectedRequestChangesNothingAndTellsTheRequester(): void {
		$id = $this->requestBob();
		try {
			$this->approvals->reject($id, $this->bob, ApprovalService::VIA_WEB);
			$this->fail('The account itself cannot decide');
		} catch (ApprovalException $e) {
			$this->assertSame(ApprovalException::SUBJECT, $e->reason);
		}
		$approval = $this->approvals->reject($id, $this->carol, ApprovalService::VIA_WEB);
		$this->assertSame(Approval::STATUS_REJECTED, $approval->getStatus());
		$this->assertFalse($this->inGroup('admin', $this->bob));
		$decided = $this->notificationsWithSubject(Notifier::SUBJECT_APPROVAL_DECIDED);
		$this->assertSame('Your request to make ' . $this->bob . ' an administrator was rejected', Server::get(Notifier::class)->prepare($decided[0], 'en')->getParsedSubject());
	}

	public function testTheRequesterMayWithdraw(): void {
		$id = $this->requestBob();
		$this->assertSame(Approval::STATUS_REJECTED, $this->approvals->reject($id, $this->alice, ApprovalService::VIA_WEB)->getStatus());
		$this->assertSame([], $this->notificationsWithSubject(Notifier::SUBJECT_APPROVAL_DECIDED), 'Nobody to tell');
	}

	public function testOnlyOneDecisionWins(): void {
		$id = $this->requestBob();
		$this->approvals->reject($id, $this->carol, ApprovalService::VIA_WEB);
		$this->expectExceptionObject(new ApprovalException(ApprovalException::NOT_PENDING));
		$this->approvals->approve($id, $this->carol, ApprovalService::VIA_WEB);
	}

	public function testExpiredRequestsEndAndTellTheRequester(): void {
		$id = $this->requestBob();
		$this->expire($id);
		$this->assertSame(1, $this->approvals->expireDue());
		$this->assertSame(Approval::STATUS_EXPIRED, $this->approvals->find($id)->getStatus());
		$decided = $this->notificationsWithSubject(Notifier::SUBJECT_APPROVAL_DECIDED);
		$this->assertSame('Your request to make ' . $this->bob . ' an administrator expired', Server::get(Notifier::class)->prepare($decided[0], 'en')->getParsedSubject());
		$this->assertSame(0, $this->approvals->expireDue());
	}

	public function testAnExpiredRequestCannotBeApprovedBeforeTheJobRan(): void {
		$id = $this->requestBob();
		$this->expire($id);
		try {
			$this->approvals->approve($id, $this->carol, ApprovalService::VIA_WEB);
			$this->fail('Expired');
		} catch (ApprovalException $e) {
			$this->assertSame(ApprovalException::EXPIRED, $e->reason);
		}
		$this->assertFalse($this->inGroup('admin', $this->bob));
		$this->assertSame(Approval::STATUS_EXPIRED, $this->approvals->find($id)->getStatus());
	}

	public function testOccIsExemptAndAlerted(): void {
		$this->act(ActorResolver::OCC, true, true);
		$this->addAsWeb('admin', $this->bob);
		$this->assertTrue($this->inGroup('admin', $this->bob));
		$this->assertSame([], $this->approvals->list(true));
		[$detection] = $this->adminChanges();
		$this->assertSame(AdminChange::EXEMPT_OCC, $this->facts($detection)['exempt']);
		$this->assertSame(Severity::High->value, $detection->getSeverity());
	}

	public function testBackgroundJobsOnTheCommandLineAreExemptAndAlerted(): void {
		$this->act(ActorResolver::CRON, true);
		$this->addAsWeb('admin', $this->bob);
		$this->assertTrue($this->inGroup('admin', $this->bob));
		[$detection] = $this->adminChanges();
		$this->assertSame(AdminChange::EXEMPT_CRON, $this->facts($detection)['exempt']);
	}

	public function testDirectoryGroupsAreExemptAndAlerted(): void {
		$directory = $this->directory([$this->bob]);
		try {
			$group = $this->createMock(IGroup::class);
			$group->method('getGID')->willReturn('admin');
			$group->expects($this->never())->method('removeUser');
			$this->act($this->alice);
			$this->dispatch(new UserAddedEvent($group, $this->user($this->bob)));
		} finally {
			Server::get(IGroupManager::class)->removeBackend($directory);
		}
		$this->assertSame([], $this->approvals->list(true));
		[$detection] = $this->adminChanges();
		$this->assertSame(AdminChange::EXEMPT_DIRECTORY, AdminChangeFacts::fromArray($this->facts($detection))->exempt);
	}

	public function testAWebAdditionWaitsAlthoughADirectoryAlsoHasTheGroup(): void {
		$directory = $this->directory([$this->dave]);
		try {
			$this->act($this->alice);
			$this->addAsWeb('admin', $this->bob);
		} finally {
			Server::get(IGroupManager::class)->removeBackend($directory);
		}
		$this->assertFalse($this->inGroup('admin', $this->bob), 'Only the membership the directory holds is exempt');
		$this->assertCount(1, $this->approvals->list(true));
	}

	public function testAnErrorInTheGateTakesTheAdditionBack(): void {
		$gate = $this->createMock(AdminGrantGate::class);
		$gate->method('decide')->willThrowException(new \RuntimeException('The settings could not be read'));
		$this->rebuild(gate: $gate);
		$this->act($this->alice);
		$this->addAsWeb('admin', $this->bob);

		$this->assertFalse($this->inGroup('admin', $this->bob), 'An error does not let the new administrator in');
		[$approval] = $this->approvals->list(true);
		$this->assertSame($this->bob, $approval->getSubjectUid());
		[$detection] = $this->adminChanges();
		$this->assertSame(AdminChange::KIND_GRANT_REQUESTED, $this->facts($detection)['kind']);
	}

	public function testAFailedRevertIsReportedWithoutARequest(): void {
		$group = $this->createMock(IGroup::class);
		$group->method('getGID')->willReturn('admin');
		$group->method('inGroup')->willReturn(true);
		$this->act($this->alice);
		$this->dispatch(new UserAddedEvent($group, $this->user($this->bob)));
		$this->assertSame([], $this->approvals->list(true));
		[$detection] = $this->adminChanges();
		$this->assertTrue($this->facts($detection)['revert_failed']);
		$this->assertSame(Severity::High->value, $detection->getSeverity());
		$this->assertNotSame([], $this->notificationsWithSubject(AdminAlerts::SUBJECT));
	}

	public function testApprovalAppliesDuringLearningMode(): void {
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::LEARNING_UNTIL, time() + 3600);
		$this->act($this->alice);
		$this->addAsWeb('admin', $this->bob);
		$this->assertFalse($this->inGroup('admin', $this->bob));
		$this->assertCount(1, $this->approvals->list(true));
	}

	public function testApprovalCanBeSwitchedOnWithTwoAdmins(): void {
		$this->requireApproval(false);
		$this->settingsEditor()->setGlobal(GlobalSettings::ADMIN_CHANGE_REQUIRE_APPROVAL, true);
		$this->assertTrue($this->appSettings()->adminChangeRequireApproval());
	}

	public function testApprovalCannotBeSwitchedOnWithFewerThanTwoAdmins(): void {
		$this->requireApproval(false);
		$check = Server::get(AdminChange::class);
		$approvers = $this->createMock(\OCA\IntrusionDetection\AdminChange\Approvers::class);
		$approvers->method('count')->willReturn(1);
		$this->overwriteService(\OCA\IntrusionDetection\AdminChange\Approvers::class, $approvers);
		try {
			$this->settingsEditor()->setGlobal(GlobalSettings::ADMIN_CHANGE_REQUIRE_APPROVAL, true);
			$this->fail('One administrator cannot switch approval on');
		} catch (InvalidParamException $e) {
			$this->assertSame('too_few_admins', $e->reason);
		} finally {
			$this->restoreService(\OCA\IntrusionDetection\AdminChange\Approvers::class);
		}
		$this->assertFalse($this->appSettings()->adminChangeRequireApproval());
		$this->assertFalse($check->validateParam(GlobalSettings::ADMIN_CHANGE_REQUIRE_APPROVAL, false), 'Switching it off is always possible');
	}

	private function delegate(string $gid): void {
		$this->createGroup($gid);
		$qb = $this->db->getQueryBuilder();
		$qb->insert('authorized_groups')
			->values(['group_id' => $qb->createNamedParameter($gid), 'class' => $qb->createNamedParameter(\OCA\Settings\Settings\Admin\Users::class)])
			->executeStatement();
		$this->rebuild();
	}

	private function requestBob(): int {
		$this->act($this->alice);
		$this->addAsWeb('admin', $this->bob);
		[$approval] = $this->approvals->list(true);
		return (int)$approval->getId();
	}

	private function expire(int $id): void {
		$approval = Server::get(ApprovalMapper::class)->findById($id);
		$approval->setExpiresAt(time() - 1);
		Server::get(ApprovalMapper::class)->update($approval);
	}

	/**
	 * Approving needs the password, which no notification can ask: the one
	 * button opens the request on the admin page, also in the clients.
	 */
	private function assertReviewedOnTheAdminPage(INotification $prepared, int $id): void {
		$this->assertStringContainsString('Approving needs your password', $prepared->getParsedMessage());
		$this->assertStringEndsWith('/settings/admin/intrusion_detection#approval-' . $id, $prepared->getLink());
		$actions = $prepared->getParsedActions();
		$this->assertSame(['Review the request'], array_map(static fn ($a): string => $a->getParsedLabel(), $actions));
		$this->assertSame('WEB', $actions[0]->getRequestType());
		$this->assertTrue($actions[0]->isPrimary());
		$this->assertSame($prepared->getLink(), $actions[0]->getLink());
	}

	/**
	 * A user directory that also has a group "admin", with these members.
	 *
	 * @param list<string> $members
	 */
	private function directory(array $members): GroupInterface {
		$directory = new class($members) extends ABackend implements INamedBackend {
			/**
			 * @param list<string> $members
			 */
			public function __construct(
				private array $members,
			) {
			}

			public function getBackendName(): string {
				return 'LDAP';
			}

			public function inGroup($uid, $gid): bool {
				return $gid === 'admin' && in_array($uid, $this->members, true);
			}

			public function getUserGroups($uid): array {
				return in_array($uid, $this->members, true) ? ['admin'] : [];
			}

			public function getGroups(string $search = '', int $limit = -1, int $offset = 0): array {
				return ['admin'];
			}

			public function groupExists($gid): bool {
				return $gid === 'admin';
			}

			public function usersInGroup($gid, $search = '', $limit = -1, $offset = 0): array {
				return $gid === 'admin' ? $this->members : [];
			}
		};
		Server::get(IGroupManager::class)->addBackend($directory);
		return $directory;
	}
}
