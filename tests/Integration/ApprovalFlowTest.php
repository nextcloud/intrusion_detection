<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AdminChange\ActorResolver;
use OCA\IntrusionDetection\AdminChange\ApprovalException;
use OCA\IntrusionDetection\AdminChange\ApprovalService;
use OCA\IntrusionDetection\AdminChange\GrantPermit;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\AdminChange\AdminChange;
use OCA\IntrusionDetection\Check\Checks\AdminChange\AdminChangeFacts;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Db\Approval;
use OCA\IntrusionDetection\Db\ApprovalMapper;
use OCA\IntrusionDetection\Definition\InvalidParamException;
use OCA\IntrusionDetection\Definition\Severity;
use OCA\IntrusionDetection\Notification\AdminAlerts;
use OCA\IntrusionDetection\Notification\Notifier;
use OCP\Group\Events\UserAddedEvent;
use OCP\IGroup;
use OCP\Notification\AlreadyProcessedException;
use OCP\Notification\IManager as INotificationManager;
use OCP\Notification\INotification;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

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
		$group = $this->createMock(IGroup::class);
		$group->method('getGID')->willReturn('admin');
		$group->method('getBackendNames')->willReturn(['LDAP']);
		$group->expects($this->never())->method('removeUser');
		$this->act($this->alice);
		$this->dispatch(new UserAddedEvent($group, $this->user($this->bob)));
		$this->assertSame([], $this->approvals->list(true));
		[$detection] = $this->adminChanges();
		$this->assertSame(AdminChange::EXEMPT_DIRECTORY, AdminChangeFacts::fromArray($this->facts($detection))->exempt);
	}

	public function testAFailedRevertIsReportedWithoutARequest(): void {
		$group = $this->createMock(IGroup::class);
		$group->method('getGID')->willReturn('admin');
		$group->method('getBackendNames')->willReturn(['Database']);
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
}
