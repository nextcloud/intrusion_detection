<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AdminChange\ApprovalException;
use OCA\IntrusionDetection\AdminChange\ApprovalService;
use OCA\IntrusionDetection\Check\Checks\StepUpFailed\StepUpFailed;
use OCA\IntrusionDetection\Check\Checks\StepUpRefused\StepUpRefused;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Confirm\ConfirmationStatus;
use OCA\IntrusionDetection\Confirm\IConfirmationMethod;
use OCA\IntrusionDetection\Confirm\LoginConfirmations;
use OCA\IntrusionDetection\Confirm\Methods\AdminApprovalMethod;
use OCA\IntrusionDetection\Controller\VerifyController;
use OCA\IntrusionDetection\Db\Approval;
use OCA\IntrusionDetection\Db\ApprovalMapper;
use OCA\IntrusionDetection\Login\SessionMarkers;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Notification\Notifier;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\SessionState\RequestTarget;
use OCP\AppFramework\Http\Attribute\NoCSRFRequired;
use OCP\AppFramework\Http\Attribute\UserRateLimit;
use OCP\AppFramework\Http\JSONResponse;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\Http\StandaloneTemplateResponse;
use OCP\IUser;
use OCP\Notification\AlreadyProcessedException;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * An administrator approves a login that nothing else can confirm
 * (concept section 11.5, method 4): the request, the waiting page and its
 * status, approval, rejection, expiry, giving up, and that nobody approves
 * their own login.
 */
#[Group('DB')]
class AdminApprovalTest extends StepUpTestCase {
	private const ADMIN = 'admin';

	private IUser $bob;

	protected function setUp(): void {
		parent::setUp();
		$this->bob = $this->user('ids-approval', null);
		$this->settingsEditor()->setGlobal(GlobalSettings::STEP_UP_ADMIN_APPROVAL, true);
		Server::get(FlaggedSources::class)->flagSource(SourceKey::fromIp($this->remoteAddress), FlaggedSources::REASON_ATTACK);
	}

	public function testALoginNothingElseCanConfirmWaitsForAnAdministrator(): void {
		$this->waitingLogin();
		$stepUp = $this->stepUp();
		$this->assertSame([IConfirmationMethod::ADMIN_APPROVAL], $stepUp?->methods);
		$approval = $this->approval();
		$this->assertSame(Approval::KIND_LOGIN, $approval->getKind());
		$this->assertSame($this->bob->getUID(), $approval->getSubjectUid());
		$this->assertSame($this->remoteAddress, $approval->getIp());
		$this->assertSame($approval->getExpiresAt(), $stepUp->deadline, 'The login may wait as long as the request');
		$this->assertGreaterThan($stepUp->started + LoginConfirmations::SESSION_TTL, $stepUp->deadline);
		$this->assertSame([], $this->detectionsOf(StepUpRefused::ID), 'Not refused');

		$this->assertNotSame([], $this->notificationsFor(self::ADMIN, Notifier::SUBJECT_APPROVAL_REQUESTED), 'The administrators are asked');
		$this->assertSame([], $this->notificationsFor($this->bob->getUID()), 'The account is not');

		$page = $this->verifyController()->show('/index.php/apps/files/');
		$this->assertInstanceOf(StandaloneTemplateResponse::class, $page);
		$this->assertSame(VerifyController::MODE_WAITING, $page->getParams()['mode']);
		$html = $page->render();
		$this->assertStringContainsString('Waiting for an administrator', $html);
		$this->assertStringContainsString('data-ids-poll=', $html);
		$this->assertStringContainsString('Cancel this login', $html);
		$this->assertStringContainsString('Remember this device', $html);
		$this->assertMatchesRegularExpression('/<button class="ids-page__secondary ids-page__check" type="submit">\s*Check now/', $html, 'Works without the script, and is not the main action as the page checks by itself');
		$this->assertStringNotContainsString(' …', $html);

		$this->assertSame(['status' => 'pending', 'retryAfter' => VerifyController::POLL_INTERVAL], $this->approvalStatus()->getData());
		$this->assertNotNull($this->rule()->check($this->state, RequestTarget::dav('PROPFIND', '/')), 'Nothing else is reachable while it waits');

		$waiting = $this->verifyController()->continueApproval();
		$this->assertInstanceOf(StandaloneTemplateResponse::class, $waiting);
		$this->assertSame('No administrator has decided yet. This page keeps checking.', $waiting->getParams()['notice']);
		$this->assertNotNull($this->stepUp(), '"Check now" before a decision changes nothing');
	}

	public function testTheLoginContinuesOnlyOnceAnotherAdministratorApproved(): void {
		$this->waitingLogin();
		$id = (int)$this->stepUp()?->approvalId;

		$this->assertRefused(ApprovalException::SUBJECT, fn () => Server::get(ApprovalService::class)->approve($id, $this->bob->getUID(), ApprovalService::VIA_WEB), 'Nobody approves their own login');
		$this->assertRefused(ApprovalException::NOT_ADMIN, fn () => Server::get(ApprovalService::class)->approve($id, $this->user('ids-approval-other', null)->getUID(), ApprovalService::VIA_WEB), 'Only administrators decide');
		$this->assertSame('pending', $this->approvalStatus()->getData()['status']);

		Server::get(ApprovalService::class)->approve($id, self::ADMIN, ApprovalService::VIA_WEB);
		$this->assertSame('approved', $this->approvalStatus()->getData()['status']);
		$this->assertNotNull($this->rule()->check($this->state, RequestTarget::dav('PROPFIND', '/')), 'Still held until the page continues');

		$response = $this->verifyController()->continueApproval('/index.php/apps/files/', '1');
		$this->assertInstanceOf(RedirectResponse::class, $response);
		$this->assertStringEndsWith('/index.php/apps/files/', $response->getRedirectURL());
		$this->assertNull($this->stepUp());
		$this->assertSame('admin_approval', $this->state->get(SessionMarkers::CONFIRMATION)['by'] ?? null);
		$this->assertNull($this->rule()->check($this->state, RequestTarget::dav('PROPFIND', '/')));
		$this->assertCount(1, $this->deviceCookiesSet, 'Remembered, as chosen');

		$this->assertRefused(ApprovalException::NOT_PENDING, fn () => Server::get(ApprovalService::class)->reject($id, self::ADMIN, ApprovalService::VIA_WEB), 'One decision only');
	}

	public function testARejectedLoginEnds(): void {
		$this->waitingLogin();
		Server::get(ApprovalService::class)->reject((int)$this->stepUp()?->approvalId, self::ADMIN, ApprovalService::VIA_WEB);
		$this->assertSame('rejected', $this->approvalStatus()->getData()['status']);

		$response = $this->verifyController()->continueApproval();
		$this->assertInstanceOf(RedirectResponse::class, $response);
		$this->assertStringContainsString('reason=rejected', $response->getRedirectURL());
		$this->assertNull($this->sessionUser, 'The session ended');
		$failed = $this->detectionsOf(StepUpFailed::ID);
		$this->assertCount(1, $failed);
		$this->assertSame(StepUpFailed::RULE_REJECTED, $failed[0]->getExplanationData()['facts']['rule'] ?? null);
		$this->assertStringContainsString('rejected', $this->verifyController()->ended(StepUpFailed::RULE_REJECTED)->render());
	}

	public function testAnExpiredRequestEndsTheLogin(): void {
		$this->waitingLogin();
		$id = (int)$this->stepUp()?->approvalId;
		$qb = $this->db->getQueryBuilder();
		$qb->update(ApprovalMapper::TABLE)->set('expires_at', $qb->createNamedParameter(time() - 1))->executeStatement();
		$this->assertSame('expired', $this->approvalStatus()->getData()['status']);
		$this->assertRefused(ApprovalException::EXPIRED, fn () => Server::get(ApprovalService::class)->approve($id, self::ADMIN, ApprovalService::VIA_WEB), 'Too late to approve');

		$response = $this->verifyController()->continueApproval();
		$this->assertInstanceOf(RedirectResponse::class, $response);
		$this->assertStringContainsString('reason=timeout', $response->getRedirectURL());
		$this->assertNull($this->sessionUser);
	}

	public function testARejectedLoginCannotAskAgain(): void {
		$this->waitingLogin();
		$asked = count($this->notificationsFor(self::ADMIN, Notifier::SUBJECT_APPROVAL_REQUESTED));
		Server::get(ApprovalService::class)->reject((int)$this->stepUp()?->approvalId, self::ADMIN, ApprovalService::VIA_WEB);

		$response = $this->verifyController()->requestApproval();
		$this->assertInstanceOf(RedirectResponse::class, $response, 'Asking again after a rejection ends the login');
		$this->assertStringContainsString('reason=rejected', $response->getRedirectURL());
		$this->assertNull($this->sessionUser, 'The session ended');
		$this->assertNull($this->stepUp());
		$failed = $this->detectionsOf(StepUpFailed::ID);
		$this->assertCount(1, $failed);
		$this->assertSame(StepUpFailed::RULE_REJECTED, $failed[0]->getExplanationData()['facts']['rule'] ?? null);
		$this->assertCount(1, Server::get(ApprovalMapper::class)->findList(false, 10, Approval::KIND_LOGIN), 'No new request');
		$this->assertCount($asked, $this->notificationsFor(self::ADMIN, Notifier::SUBJECT_APPROVAL_REQUESTED), 'The administrators are not asked again');
	}

	public function testAnExpiredRequestCannotBeAskedAgain(): void {
		$this->waitingLogin();
		$qb = $this->db->getQueryBuilder();
		$qb->update(ApprovalMapper::TABLE)->set('expires_at', $qb->createNamedParameter(time() - 1))->executeStatement();

		$response = $this->verifyController()->requestApproval();
		$this->assertInstanceOf(RedirectResponse::class, $response);
		$this->assertStringContainsString('reason=timeout', $response->getRedirectURL());
		$this->assertNull($this->sessionUser);
		$this->assertSame(StepUpFailed::RULE_TIMEOUT, $this->detectionsOf(StepUpFailed::ID)[0]->getExplanationData()['facts']['rule'] ?? null);
		$this->assertSame(0, $this->pendingFor($this->bob->getUID()), 'No new request');
	}

	public function testALoginPastItsDeadlineCannotAskAnAdministratorToWaitLonger(): void {
		$carol = $this->user('ids-approval-late', 'carol@example.com');
		$this->startSession($carol);
		$this->login($carol);
		$stepUp = $this->stepUp();
		$this->assertNotNull($stepUp);
		$this->service()->update($stepUp->withDeadline(time() - 1));

		$block = $this->rule()->check($this->state, RequestTarget::app($this->verifyController(), 'requestApproval', 'POST', '/index.php/apps/intrusion_detection/verify/approval'));
		$this->assertNotNull($block, 'The rule ends it before the verify page is reached');
		$this->assertStringContainsString('reason=timeout', (string)$block->redirectUrl);
		$this->assertNull($this->stepUp());
		$this->assertSame(0, $this->pendingFor($carol->getUID()), 'Nobody was asked');
	}

	public function testAnApprovalLetsTheLoginWaitUntilItExpires(): void {
		$this->waitingLogin();
		$stepUp = $this->stepUp();
		$this->assertNotNull($stepUp);
		$this->assertSame($this->approval()->getExpiresAt(), $stepUp->deadline);
		$this->assertLessThan($stepUp->started + LoginConfirmations::SESSION_TTL + AdminApprovalMethod::TTL, $stepUp->deadline + 1, 'Never beyond the login\'s own time plus one approval');
	}

	public function testTheUserCanGiveUpWaiting(): void {
		$this->waitingLogin();
		$id = (int)$this->stepUp()?->approvalId;
		$response = $this->verifyController()->cancelApproval();
		$this->assertInstanceOf(RedirectResponse::class, $response);
		$this->assertNull($this->sessionUser);
		$approval = Server::get(ApprovalMapper::class)->findById($id);
		$this->assertSame(Approval::STATUS_REJECTED, $approval->getStatus());
		$this->assertSame($this->bob->getUID(), $approval->getDecidedBy(), 'Withdrawn by the account');
		$this->assertSame([], $this->detectionsOf(StepUpFailed::ID), 'Giving up is not an attack');
		$this->assertSame(0, $this->unconfirmedRows());
	}

	public function testWithAnEmailAddressTheCodeComesFirstAndAnAdministratorCanBeAskedInstead(): void {
		$carol = $this->user('ids-approval-mail', 'carol@example.com');
		$this->startSession($carol);
		$this->login($carol);
		$this->assertSame([IConfirmationMethod::EMAIL_CODE, IConfirmationMethod::ADMIN_APPROVAL], $this->stepUp()?->methods);
		$this->assertNull($this->stepUp()?->approvalId, 'Nobody is asked yet');
		$page = $this->verifyController()->show();
		$this->assertInstanceOf(StandaloneTemplateResponse::class, $page);
		$this->assertTrue($page->getParams()['askAdmin']);
		$this->assertStringContainsString('Ask an administrator', $page->render());

		$waiting = $this->verifyController()->requestApproval();
		$this->assertInstanceOf(StandaloneTemplateResponse::class, $waiting);
		$this->assertSame(VerifyController::MODE_WAITING, $waiting->getParams()['mode']);
		$this->assertNotNull($this->stepUp()?->approvalId);
		$this->assertTrue($waiting->getParams()['hasCode']);
		$codePage = $this->verifyController()->show('', 'code');
		$this->assertInstanceOf(StandaloneTemplateResponse::class, $codePage);
		$this->assertSame(VerifyController::MODE_CODE, $codePage->getParams()['mode']);
		$this->assertStringContainsString('Back to waiting for an administrator', $codePage->render());

		$this->verifyController()->requestApproval();
		$this->assertSame(1, $this->pendingFor($carol->getUID()), 'Asking again reuses the request');
	}

	public function testAnAccountCannotFloodTheAdministrators(): void {
		for ($i = 0; $i < ApprovalService::MAX_PENDING_LOGINS; $i++) {
			$this->waitingLogin();
		}
		$this->session->clear();
		$this->startSession($this->bob);
		$this->login($this->bob);
		$this->assertSame(ConfirmationStatus::Refused, $this->stepUp()?->status, 'Too many waiting logins: the policy decides');
		$this->assertSame(ApprovalService::MAX_PENDING_LOGINS, $this->pendingFor($this->bob->getUID()));
	}

	public function testOffByDefault(): void {
		$this->settingsEditor()->setGlobal(GlobalSettings::STEP_UP_ADMIN_APPROVAL, false);
		$this->startSession($this->bob);
		$this->login($this->bob);
		$this->assertSame(ConfirmationStatus::Refused, $this->stepUp()?->status);
		$this->assertSame(0, $this->pendingFor($this->bob->getUID()));
	}

	public function testTheAdministratorsNotificationExplainsTheLogin(): void {
		$this->waitingLogin();
		$notification = $this->notificationsFor(self::ADMIN, Notifier::SUBJECT_APPROVAL_REQUESTED)[0];
		$prepared = Server::get(Notifier::class)->prepare(clone $notification, 'en');
		$this->assertSame('Approve the login of ' . $this->bob->getUID() . '?', $prepared->getParsedSubject());
		$this->assertStringContainsString('from the address ' . $this->remoteAddress, $prepared->getParsedMessage());
		$this->assertStringEndsWith('#settings-approvals', $prepared->getLink());
		$actions = $prepared->getParsedActions();
		$this->assertSame(['Review the login'], array_map(static fn ($a): string => $a->getParsedLabel(), $actions), 'one button, not "Reject" as a second primary one');
		$this->assertSame('WEB', $actions[0]->getRequestType());
		$this->assertStringEndsWith('#settings-approvals', $actions[0]->getLink());

		Server::get(ApprovalService::class)->approve((int)$this->stepUp()?->approvalId, self::ADMIN, ApprovalService::VIA_WEB);
		$this->expectException(AlreadyProcessedException::class);
		Server::get(Notifier::class)->prepare(clone $notification, 'en');
	}

	public function testTheExpiryJobEndsWaitingRequests(): void {
		$this->waitingLogin();
		$qb = $this->db->getQueryBuilder();
		$qb->update(ApprovalMapper::TABLE)->set('expires_at', $qb->createNamedParameter(time() - 1))->executeStatement();
		$this->assertSame(1, Server::get(ApprovalService::class)->expireDue());
		$this->assertSame(Approval::STATUS_EXPIRED, $this->approval()->getStatus());
	}

	public function testTheStatusEndpointIsCheapAndTheWritesAreProtected(): void {
		$status = new \ReflectionMethod(VerifyController::class, 'approvalStatus');
		$this->assertCount(1, $status->getAttributes(NoCSRFRequired::class), 'A read-only GET');
		$this->assertCount(1, $status->getAttributes(UserRateLimit::class));
		foreach (['requestApproval', 'continueApproval', 'cancelApproval'] as $write) {
			$method = new \ReflectionMethod(VerifyController::class, $write);
			$this->assertSame([], $method->getAttributes(NoCSRFRequired::class), $write . ' is CSRF-protected');
			$this->assertCount(1, $method->getAttributes(UserRateLimit::class), $write . ' is rate limited');
		}
		$this->assertSame(['status' => 'none', 'retryAfter' => VerifyController::POLL_INTERVAL], $this->approvalStatus()->getData(), 'Without a waiting login');
	}

	private function waitingLogin(): void {
		$this->session->clear();
		$this->nextRequest();
		$this->startSession($this->bob);
		$this->login($this->bob);
		$this->assertSame(ConfirmationStatus::Pending, $this->stepUp()?->status);
		$this->assertNotNull($this->stepUp()?->approvalId);
	}

	private function approvalStatus(): JSONResponse {
		return $this->verifyController()->approvalStatus();
	}

	private function approval(): Approval {
		$list = Server::get(ApprovalMapper::class)->findList(false, 10, Approval::KIND_LOGIN);
		$this->assertNotSame([], $list);
		return $list[0];
	}

	private function pendingFor(string $uid): int {
		return Server::get(ApprovalMapper::class)->countPendingFor(Approval::KIND_LOGIN, $uid, time());
	}

	/**
	 * @param \Closure(): mixed $decide
	 */
	private function assertRefused(string $reason, \Closure $decide, string $message): void {
		try {
			$decide();
			$this->fail($message);
		} catch (ApprovalException $e) {
			$this->assertSame($reason, $e->reason, $message);
		}
	}
}
