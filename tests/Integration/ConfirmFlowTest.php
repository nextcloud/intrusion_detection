<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AdminChange\ApprovalService;
use OCA\IntrusionDetection\Check\Checks\StepUpFailed;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Confirm\IConfirmationMethod;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCA\IntrusionDetection\Controller\ConfirmController;
use OCA\IntrusionDetection\Controller\VerifyController;
use OCA\IntrusionDetection\Db\Approval;
use OCA\IntrusionDetection\Db\ApprovalMapper;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Notification\Notifier;
use OCA\IntrusionDetection\SessionState\RequestTarget;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\BruteForceProtection;
use OCP\AppFramework\Http\Attribute\NoCSRFRequired;
use OCP\AppFramework\Http\Attribute\PublicPage;
use OCP\AppFramework\Http\Attribute\UserRateLimit;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\Http\Response;
use OCP\AppFramework\Http\StandaloneTemplateResponse;
use OCP\Authentication\TwoFactorAuth\IProvider;
use OCP\Authentication\TwoFactorAuth\TwoFactorProviderChallengePassed;
use OCP\IUser;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * The confirm page (concept sections 11.13 and 15.2): the methods of
 * logins without a remembered device, the code lifecycle, the second
 * factor asked again, an administrator's approval, and refusals.
 */
#[Group('DB')]
class ConfirmFlowTest extends SensitiveTestCase {
	private const BACK = '/index.php/settings/user/security';

	private IUser $alice;

	protected function setUp(): void {
		parent::setUp();
		$this->alice = $this->user('ids-confirm', 'alice@example.com');
		$this->startSession($this->alice);
		$this->route = 'settings.authsettings.create';
		$this->state->set(SessionState::CONFIRMATION, ['uid' => $this->alice->getUID(), 'by' => 'none', 'policies' => ['risky_network'], 'at' => time()]);
	}

	public function testTheMethodsAreThoseOfLoginsWithoutARememberedDevice(): void {
		$this->knownDevices()->remember($this->alice, null, 'Firefox');
		$this->settings->setGlobal(GlobalSettings::STEP_UP_KNOWN_DEVICE_OK_FOR, ['flagged_source', 'protected_account', 'risky_network', 'risk_high']);
		$this->nextRequest();
		$this->assertNotNull($this->knownDevices()->recognise($this->alice->getUID()), 'The browser is remembered');

		$page = $this->confirmController()->show(self::BACK);
		$this->assertSame([IConfirmationMethod::EMAIL_CODE], $this->pending()?->methods, 'A remembered device never confirms an action that runs on it');
		$this->assertSame(['sensitive_action'], $this->pending()?->policies);
		$this->assertSame(ConfirmController::MODE_CODE, $this->paramOf($page, 'mode'));
		$this->assertTrue($this->paramOf($page, 'hasCode'));
		$this->assertFalse($this->paramOf($page, 'canRemember'), 'Nothing to remember here');
		$html = $page->render();
		$this->assertStringContainsString('a***@example.com', $html);
		$this->assertStringContainsString('action="/index.php/apps/intrusion_detection/confirm"', $html);
		$this->assertStringNotContainsString('482915', $html);
		$this->assertStringContainsString('Your login could not be confirmed, so changes like this need it now.', $html);
		$this->assertCount(1, $this->mailed);
		$this->assertNull($this->stepUp(), 'The session works normally meanwhile');
	}

	public function testTheRightCodeConfirmsAndGoesBackToThePage(): void {
		$this->assertNotNull($this->sensitiveRule()->check($this->state, $this->target()), 'Refused before');
		$this->confirmController()->show(self::BACK);
		$response = $this->confirmController()->confirm('482915', self::BACK);
		$this->assertInstanceOf(RedirectResponse::class, $response);
		$this->assertStringEndsWith(self::BACK, $response->getRedirectURL());
		$this->assertNull($this->pending());
		$this->assertSame('email_code', $this->state->get(SessionState::SENSITIVE)['by'] ?? null);
		$this->assertNull($this->sensitiveRule()->check($this->state, $this->target()), 'The user repeats the action, and it goes ahead');
		$this->assertContains('Intrusion detection: sensitive action of ' . $this->alice->getUID() . ' confirmed with email_code', $this->audited);

		$again = $this->confirmController()->show(self::BACK);
		$this->assertInstanceOf(RedirectResponse::class, $again, 'Confirmed recently: straight back');
		$this->assertCount(1, $this->mailed, 'No second code');
	}

	public function testTheConfirmationLastsTheConfiguredTime(): void {
		$this->settings->setGlobal(GlobalSettings::SENSITIVE_CONFIRM_TTL, 60);
		$this->confirmController()->show(self::BACK);
		$this->confirmController()->confirm('482915', self::BACK);
		$confirmed = $this->state->get(SessionState::SENSITIVE);
		$this->state->set(SessionState::SENSITIVE, ['confirmedAt' => (int)$confirmed['confirmedAt'] - 61] + $confirmed);
		$this->assertNotNull($this->sensitiveRule()->check($this->state, $this->target()));
		$this->assertInstanceOf(StandaloneTemplateResponse::class, $this->confirmController()->show(self::BACK), 'Asked again');
	}

	public function testFiveWrongCodesEndTheSession(): void {
		$this->confirmController()->show(self::BACK);
		for ($i = 0; $i < 4; $i++) {
			$response = $this->confirmController()->confirm('000000', self::BACK);
			$this->assertSame(Http::STATUS_FORBIDDEN, $response->getStatus());
			$this->assertTrue($response->isThrottled());
		}
		$response = $this->confirmController()->confirm('000000', self::BACK);
		$this->assertInstanceOf(RedirectResponse::class, $response);
		$this->assertStringContainsString('/apps/intrusion_detection/verify/ended?reason=' . ConfirmController::ENDED_ATTEMPTS, $response->getRedirectURL());
		$this->assertTrue($response->isThrottled());
		$this->assertNull($this->sessionUser, 'Logged out');

		$detections = $this->detectionsOf(StepUpFailed::ID);
		$this->assertCount(1, $detections);
		$facts = $detections[0]->getExplanationData()['facts'];
		$this->assertTrue($facts['action']);
		$this->assertSame(StepUpFailed::RULE_ATTEMPTS, $facts['rule']);
		$l = Server::get(IFactory::class)->get('intrusion_detection', 'en');
		$narrative = implode(' ', Server::get(NarrativeBuilder::class)->build($detections[0], $l)->happened);
		$this->assertStringContainsString('tried a sensitive action', $narrative);
		$this->assertStringContainsString('5 wrong codes were entered, so the session was ended.', $narrative);

		$ended = $this->verifyController()->ended(ConfirmController::ENDED_ATTEMPTS);
		$this->assertSame('Your session was ended', $ended->getParams()['title']);
	}

	public function testTheSecondFactorComesFirstAndIsAskedAgainThroughCore(): void {
		$this->hasSecondFactor = true;
		$page = $this->confirmController()->show(self::BACK);
		$this->assertSame([IConfirmationMethod::SECOND_FACTOR, IConfirmationMethod::EMAIL_CODE], $this->pending()?->methods);
		$this->assertSame([], $this->mailed, 'No email while the second factor is offered first');
		$this->assertTrue($this->paramOf($page, 'secondFactor'));
		$this->assertFalse($this->paramOf($page, 'hasCode'));
		$this->assertSame('Send a code by email', $this->paramOf($page, 'resendLabel'));
		$this->assertStringContainsString('Confirm with your second factor', $page->render());

		$response = $this->confirmController()->secondFactor(self::BACK);
		$this->assertInstanceOf(RedirectResponse::class, $response);
		$this->assertSame('/index.php/login/challenge?redirect_url=back', $response->getRedirectURL(), 'Core\'s challenge, asked again in the running session');
		$this->assertTrue($this->pending()?->secondFactorRequested);

		$this->challengeListener()->handle(new TwoFactorProviderChallengePassed($this->alice, $this->createMock(IProvider::class)));
		$this->assertNull($this->pending());
		$this->assertSame('second_factor', $this->state->get(SessionState::SENSITIVE)['by'] ?? null);
		$this->assertInstanceOf(RedirectResponse::class, $this->confirmController()->show(self::BACK), 'Back where the challenge returns to');
	}

	public function testAnEmailCodeCanBeAskedForInsteadOfTheSecondFactor(): void {
		$this->hasSecondFactor = true;
		$this->confirmController()->show(self::BACK);
		$page = $this->confirmController()->resend(self::BACK);
		$this->assertTrue($this->paramOf($page, 'hasCode'));
		$this->assertCount(1, $this->mailed);
		$this->assertInstanceOf(RedirectResponse::class, $this->confirmController()->confirm('482915', self::BACK));
	}

	public function testASolvedSecondFactorThatWasNotAskedForConfirmsNoAction(): void {
		$this->hasSecondFactor = true;
		$this->confirmController()->show(self::BACK);
		$this->challengeListener()->handle(new TwoFactorProviderChallengePassed($this->alice, $this->createMock(IProvider::class)));
		$this->assertNotNull($this->pending());
		$this->assertNull($this->state->get(SessionState::SENSITIVE)['confirmedAt'] ?? null);
	}

	public function testWithoutAnyMethodThePageSaysSo(): void {
		$bob = $this->user('ids-confirm-bob', null);
		$this->startSession($bob);
		$page = $this->confirmController()->show(self::BACK);
		$this->assertSame(Http::STATUS_FORBIDDEN, $page->getStatus());
		$this->assertSame(ConfirmController::MODE_REFUSED, $this->paramOf($page, 'mode'));
		$this->assertSame('This action needs extra confirmation, but your account has no email address or second factor. Ask your administrator.', $this->paramOf($page, 'lead'));
		$this->assertNotNull($this->sessionUser, 'The session goes on; only the action is refused');
		$this->assertSame([], $this->mailed);
	}

	public function testAnAdministratorCanApproveTheAction(): void {
		$bob = $this->user('ids-confirm-bob', null);
		$this->startSession($bob);
		$this->settings->setGlobal(GlobalSettings::STEP_UP_ADMIN_APPROVAL, true);
		$page = $this->confirmController()->show(self::BACK);
		$this->assertSame(ConfirmController::MODE_WAITING, $this->paramOf($page, 'mode'));
		$this->assertSame('An administrator needs to confirm this. You can keep this page open; it continues automatically once approved.', $this->paramOf($page, 'lead'));
		$this->assertSame('/index.php/apps/intrusion_detection/confirm/approval/status', $this->paramOf($page, 'statusUrl'));

		$approval = Server::get(ApprovalMapper::class)->findById((int)$this->pending()?->approvalId);
		$this->assertSame(Approval::KIND_LOGIN, $approval->getKind());
		$this->assertTrue($approval->isSensitiveAction());
		$requested = $this->notificationsFor('admin', Notifier::SUBJECT_APPROVAL_REQUESTED);
		$this->assertNotSame([], $requested);
		$prepared = Server::get(Notifier::class)->prepare($requested[0], 'en');
		$this->assertSame('Approve a sensitive action of ' . $bob->getUID() . '?', $prepared->getParsedSubject());

		$this->assertSame('pending', $this->confirmController()->approvalStatus()->getData()['status']);
		Server::get(ApprovalService::class)->approve($approval->getId(), 'admin', ApprovalService::VIA_WEB);
		$this->assertSame('approved', $this->confirmController()->approvalStatus()->getData()['status']);
		$response = $this->confirmController()->continueApproval(self::BACK);
		$this->assertInstanceOf(RedirectResponse::class, $response);
		$this->assertSame('admin_approval', $this->state->get(SessionState::SENSITIVE)['by'] ?? null);
	}

	public function testGivingUpGoesBackWithoutEndingTheSession(): void {
		$bob = $this->user('ids-confirm-bob', null);
		$this->startSession($bob);
		$this->settings->setGlobal(GlobalSettings::STEP_UP_ADMIN_APPROVAL, true);
		$this->confirmController()->show(self::BACK);
		$id = (int)$this->pending()?->approvalId;
		$response = $this->confirmController()->cancelApproval(self::BACK);
		$this->assertInstanceOf(RedirectResponse::class, $response);
		$this->assertStringEndsWith(self::BACK, $response->getRedirectURL());
		$this->assertNull($this->pending());
		$this->assertNotNull($this->sessionUser);
		$this->assertSame(Approval::STATUS_REJECTED, Server::get(ApprovalMapper::class)->findById($id)->getStatus(), 'Withdrawn');
		$this->assertSame([], $this->detectionsOf(StepUpFailed::ID));
	}

	public function testARejectionEndsTheSession(): void {
		$bob = $this->user('ids-confirm-bob', null);
		$this->startSession($bob);
		$this->settings->setGlobal(GlobalSettings::STEP_UP_ADMIN_APPROVAL, true);
		$this->confirmController()->show(self::BACK);
		Server::get(ApprovalService::class)->reject((int)$this->pending()?->approvalId, 'admin', ApprovalService::VIA_WEB);
		$response = $this->confirmController()->continueApproval(self::BACK);
		$this->assertStringContainsString('reason=' . ConfirmController::ENDED_REJECTED, $response->getHeaders()['Location'] ?? '');
		$this->assertNull($this->sessionUser);
		$this->assertCount(1, $this->detectionsOf(StepUpFailed::ID));
	}

	public function testOnlyLocalPagesAreReturnedTo(): void {
		$this->confirmController()->show('https://evil.example/');
		$response = $this->confirmController()->confirm('482915', 'https://evil.example/');
		$this->assertInstanceOf(RedirectResponse::class, $response);
		$this->assertStringNotContainsString('evil', $response->getRedirectURL());
	}

	public function testTheEndpointsAreProtected(): void {
		$class = new \ReflectionClass(ConfirmController::class);
		foreach (['confirm', 'resend', 'secondFactor', 'requestApproval', 'continueApproval', 'cancelApproval'] as $method) {
			$reflection = $class->getMethod($method);
			$this->assertSame([], $reflection->getAttributes(NoCSRFRequired::class), $method . ' is CSRF-protected');
			$this->assertNotSame([], $reflection->getAttributes(UserRateLimit::class), $method . ' is rate limited');
		}
		$this->assertNotSame([], $class->getMethod('confirm')->getAttributes(BruteForceProtection::class));
		foreach ($class->getMethods(\ReflectionMethod::IS_PUBLIC) as $method) {
			$this->assertSame([], $method->getAttributes(PublicPage::class), $method->getName() . ' needs a logged-in user');
		}
		$this->assertSame(VerifyController::BRUTE_FORCE_ACTION, ConfirmController::BRUTE_FORCE_ACTION, 'Wrong codes count together with the verify page');
	}

	private function pending(): ?StepUpState {
		return $this->confirmations()->current($this->sessionUser ?? $this->alice);
	}

	private function target(): RequestTarget {
		return RequestTarget::app($this->createMock(\OCP\AppFramework\Controller::class), 'create', 'POST', '/index.php/settings/personal/authtokens');
	}

	private function paramOf(Response $response, string $name): mixed {
		$this->assertInstanceOf(StandaloneTemplateResponse::class, $response);
		return $response->getParams()[$name] ?? null;
	}
}
