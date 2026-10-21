<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Controller\PasswordChangeController;
use OCA\IntrusionDetection\Http\LocalRedirect;
use OCA\IntrusionDetection\Listener\PasswordChangeLoginListener;
use OCA\IntrusionDetection\Listener\PasswordUpdatedListener;
use OCA\IntrusionDetection\Notification\AdminNotices;
use OCA\IntrusionDetection\Response\PasswordChangeFlag;
use OCA\IntrusionDetection\Response\PasswordChangeService;
use OCA\IntrusionDetection\SessionState\Rules\PasswordChangeRule;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\Http\StandaloneTemplateResponse;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\HintException;
use OCP\IRequest;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\IUserManager;
use OCP\L10N\IFactory;
use OCP\Security\Events\ValidatePasswordPolicyEvent;
use OCP\Server;
use OCP\User\Events\PasswordUpdatedEvent;
use OCP\User\Events\UserLoggedInEvent;
use OCP\User\Events\UserLoggedInWithCookieEvent;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;

/**
 * Forced password change (concept section 11.7): the requirement, the
 * login listener that marks sessions, the password page, and lifting it.
 */
#[Group('DB')]
class PasswordChangeTest extends AccountTestCase {
	private PasswordChangeService $passwords;
	private PasswordChangeFlag $flag;
	private SessionState $state;
	private IUser $user;
	private string $password;
	/** @var array<string, string> */
	private array $headers = [];
	/** @var \Closure(ValidatePasswordPolicyEvent): void */
	private \Closure $policy;

	protected function setUp(): void {
		parent::setUp();
		$this->passwords = Server::get(PasswordChangeService::class);
		$this->flag = Server::get(PasswordChangeFlag::class);
		$this->state = new SessionState($this->session, Server::get(LoggerInterface::class));
		$this->user = $this->newUser('ids-pw', 'pw@example.com');
		$this->password = 'A-long-test-password-' . $this->user->getUID();
		$this->policy = static function (ValidatePasswordPolicyEvent $event): void {
			if (strlen($event->getPassword()) < 12) {
				throw new HintException('Password too short', 'Passwords must be at least 12 characters <long>.');
			}
		};
		Server::get(IEventDispatcher::class)->addListener(ValidatePasswordPolicyEvent::class, $this->policy);
	}

	protected function tearDown(): void {
		Server::get(IEventDispatcher::class)->removeListener(ValidatePasswordPolicyEvent::class, $this->policy);
		parent::tearDown();
	}

	public function testRequiringSetsTheFlagOnce(): void {
		$this->assertSame(PasswordChangeService::STATE_REQUIRED, $this->passwords->require($this->user->getUID(), 42));
		$since = $this->flag->requiredSince($this->user->getUID());
		$this->assertNotNull($since);
		$this->passwords->require($this->user->getUID(), 43);
		$this->assertSame($since, $this->flag->requiredSince($this->user->getUID()), 'An earlier requirement is kept');
		$this->assertSame(PasswordChangeService::STATE_NO_USER, $this->passwords->require('no-such-user-' . $this->user->getUID()));
	}

	public function testABackendThatCannotChangePasswordsAsksTheAdminsInstead(): void {
		$external = $this->createMock(IUser::class);
		$external->method('getUID')->willReturn('ldap-alice');
		$external->method('canChangePassword')->willReturn(false);
		$users = $this->createMock(IUserManager::class);
		$users->method('get')->willReturn($external);
		$service = new PasswordChangeService($this->flag, $users, Server::get(AdminNotices::class), Server::get(AuditLogger::class));

		$this->assertSame(PasswordChangeService::STATE_EXTERNAL, $service->require('ldap-alice', 7, 'second_factor_failed'));
		$this->assertFalse($this->flag->isRequired('ldap-alice'), 'No requirement the user cannot meet');
		$notices = $this->notificationsFor('admin', AdminNotices::SUBJECT_PASSWORD_EXTERNAL);
		$this->assertCount(1, $notices);
		$this->assertSame(['uid' => 'ldap-alice', 'detection' => 7], $notices[0]->getSubjectParameters());

		// Aggregated: once per account and hour.
		$service->require('ldap-alice', 8, 'second_factor_failed');
		$this->assertCount(1, $this->notificationsFor('admin', AdminNotices::SUBJECT_PASSWORD_EXTERNAL));
	}

	public function testTheAdminsAreToldWhereThePasswordMustBeReset(): void {
		$notification = Server::get(\OCP\Notification\IManager::class)->createNotification();
		$notification->setApp(Application::APP_ID)
			->setUser('admin')
			->setDateTime(new \DateTime())
			->setObject(AdminNotices::OBJECT_TYPE, '1')
			->setSubject(AdminNotices::SUBJECT_PASSWORD_EXTERNAL, ['uid' => $this->user->getUID(), 'detection' => null]);
		$prepared = Server::get(\OCA\IntrusionDetection\Notification\Notifier::class)->prepare($notification, 'en');
		$this->assertSame('Reset the password of ' . $this->user->getUID() . ' in the external directory', $prepared->getParsedSubject());
		$this->assertStringContainsString('managed outside Nextcloud (Database)', $prepared->getParsedMessage());
		$this->assertStringEndsWith('/settings/admin/intrusion_detection', $prepared->getLink());
	}

	/**
	 * @return array<string, array{array<string, string>, bool, bool, ?string}>
	 */
	public static function logins(): array {
		return [
			'login form' => [[], false, false, PasswordChangeRule::MODE_REDIRECT],
			'remembered login' => [[], false, true, PasswordChangeRule::MODE_REDIRECT],
			'browser session restored from its token' => [[], true, false, PasswordChangeRule::MODE_REDIRECT],
			'Basic auth with the password' => [['Authorization' => 'Basic YWxpY2U6c2VjcmV0'], false, false, PasswordChangeRule::MODE_REFUSE],
			'Basic auth via PHP_AUTH_USER' => [['PHP_AUTH_USER' => 'alice'], false, false, PasswordChangeRule::MODE_REFUSE],
			'Basic auth with an app password' => [['Authorization' => 'Basic YWxpY2U6c2VjcmV0'], true, false, null],
			'Bearer token' => [['Authorization' => 'Bearer abc'], true, false, null],
		];
	}

	/**
	 * @param array<string, string> $headers
	 */
	#[DataProvider('logins')]
	public function testLoginsAreMarkedByHowTheyHappened(array $headers, bool $tokenLogin, bool $cookie, ?string $mode): void {
		$this->passwords->require($this->user->getUID());
		$this->headers = $headers;
		$this->loginListener()->handle($cookie
			? new UserLoggedInWithCookieEvent($this->user, null)
			: new UserLoggedInEvent($this->user, $this->user->getUID(), 'irrelevant', $tokenLogin));
		$marker = $this->state->get(SessionState::PASSWORD_CHANGE);
		$this->assertSame($mode, $marker['mode'] ?? null);
		if ($mode !== null) {
			$this->assertSame($this->user->getUID(), $marker['uid']);
		}
	}

	public function testLoginsOfAccountsWithoutARequirementAreNotMarked(): void {
		$this->loginListener()->handle(new UserLoggedInEvent($this->user, $this->user->getUID(), 'irrelevant', false));
		$this->assertTrue($this->state->isEmpty());
	}

	public function testThePageAsksForTheCurrentAndANewPassword(): void {
		$this->requireAndMark();
		$response = $this->controller()->show('/apps/files/');
		$this->assertInstanceOf(StandaloneTemplateResponse::class, $response);
		$this->assertSame(Http::STATUS_OK, $response->getStatus());
		$this->assertSame('guest', $response->getRenderAs());
		$this->assertSame('/apps/files/', $response->getParams()['redirect_url']);
		$html = $response->render();
		$this->assertStringContainsString('name="currentPassword"', $html);
		$this->assertStringContainsString('name="newPassword"', $html);
		$this->assertStringContainsString('name="requesttoken"', $html);
		$this->assertStringContainsString('autocomplete="new-password"', $html);
	}

	public function testWithoutARequirementThePageContinuesAtOnce(): void {
		$this->state->set(SessionState::PASSWORD_CHANGE, ['uid' => $this->user->getUID(), 'mode' => PasswordChangeRule::MODE_REDIRECT]);
		$response = $this->controller()->show('/apps/files/');
		$this->assertInstanceOf(RedirectResponse::class, $response);
		$this->assertStringEndsWith('/apps/files/', $response->getRedirectURL());
		$this->assertTrue($this->state->isEmpty(), 'A stale marker is dropped');
	}

	public function testAWrongCurrentPasswordIsThrottled(): void {
		$this->requireAndMark();
		$response = $this->controller()->change('wrong', 'A-brand-new-password-1', 'A-brand-new-password-1');
		$this->assertSame(Http::STATUS_FORBIDDEN, $response->getStatus());
		$this->assertTrue($response->isThrottled());
		$this->assertSame('Your current password is not correct.', $this->errorOf($response));
		$this->assertTrue($this->flag->isRequired($this->user->getUID()));
	}

	/**
	 * @return array<string, array{string, string, string}>
	 */
	public static function invalidNewPasswords(): array {
		return [
			'empty' => ['', '', 'Enter a new password.'],
			'not repeated the same' => ['A-brand-new-password-1', 'A-brand-new-password-2', 'The two new passwords are not the same. Type the new password twice.'],
			'the policy refuses it' => ['short', 'short', 'Passwords must be at least 12 characters <long>.'],
		];
	}

	#[DataProvider('invalidNewPasswords')]
	public function testInvalidNewPasswordsAreExplained(string $new, string $repeat, string $error): void {
		$this->requireAndMark();
		$response = $this->controller()->change($this->password, $new, $repeat);
		$this->assertSame(Http::STATUS_BAD_REQUEST, $response->getStatus());
		$this->assertSame($error, $this->errorOf($response));
		$this->assertFalse($response->isThrottled());
		$this->assertTrue($this->flag->isRequired($this->user->getUID()));
	}

	public function testThePolicyMessageIsShownEscaped(): void {
		$this->requireAndMark();
		$response = $this->controller()->change($this->password, 'short', 'short');
		$this->assertInstanceOf(StandaloneTemplateResponse::class, $response);
		$html = $response->render();
		$this->assertStringContainsString('Passwords must be at least 12 characters &lt;long&gt;.', $html);
		$this->assertStringNotContainsString('<long>', $html);
		$this->assertStringContainsString('role="alert"', $html);
	}

	public function testTheCurrentPasswordCannotBeChosenAgain(): void {
		$this->requireAndMark();
		$response = $this->controller()->change($this->password, $this->password, $this->password);
		$this->assertSame('Choose a password that is different from your current one.', $this->errorOf($response));
	}

	public function testANewPasswordLiftsTheRequirementAndContinues(): void {
		$this->requireAndMark();
		$response = $this->controller()->change($this->password, 'A-brand-new-password-1', 'A-brand-new-password-1', '/apps/files/?dir=/Photos');
		$this->assertInstanceOf(RedirectResponse::class, $response);
		$this->assertStringEndsWith('/apps/files/?dir=/Photos', $response->getRedirectURL());
		$this->assertNotFalse(Server::get(IUserManager::class)->checkPassword($this->user->getUID(), 'A-brand-new-password-1'));
		$this->assertFalse($this->flag->isRequired($this->user->getUID()));
		$this->assertTrue($this->state->isEmpty());
	}

	/**
	 * @return array<string, array{string}>
	 */
	public static function unsafeTargets(): array {
		return [
			'another host' => ['https://evil.example/'],
			'protocol-relative' => ['//evil.example/'],
			'backslash' => ['/\\evil.example'],
			'control character' => ["/apps/files/\r\nX: y"],
			'the password page itself' => ['/index.php/apps/intrusion_detection/password'],
		];
	}

	#[DataProvider('unsafeTargets')]
	public function testOnlyLocalPathsAreContinuedTo(string $target): void {
		$response = $this->controller()->show($target);
		$this->assertInstanceOf(RedirectResponse::class, $response);
		$this->assertSame(Server::get(IURLGenerator::class)->linkToDefaultPageUrl(), $response->getRedirectURL());
	}

	public function testAPasswordChangedElsewhereLiftsTheRequirement(): void {
		$this->requireAndMark();
		$listener = new PasswordUpdatedListener($this->passwords, $this->state, $this->userSession, Server::get(LoggerInterface::class));
		$listener->handle(new PasswordUpdatedEvent($this->user, 'A-brand-new-password-1'));
		$this->assertFalse($this->flag->isRequired($this->user->getUID()));
		$this->assertTrue($this->state->isEmpty());
	}

	public function testAnAccountWhosePasswordIsManagedElsewhereIsNotSentToThePage(): void {
		$this->flag->set('ldap-bob');
		$external = $this->createMock(IUser::class);
		$external->method('getUID')->willReturn('ldap-bob');
		$external->method('canChangePassword')->willReturn(false);
		$this->loginListener()->handle(new UserLoggedInEvent($external, 'ldap-bob', 'irrelevant', false));
		$this->assertTrue($this->state->isEmpty());
		$this->assertFalse($this->flag->isRequired('ldap-bob'));
		$this->assertCount(1, $this->notificationsFor('admin', AdminNotices::SUBJECT_PASSWORD_EXTERNAL));
	}

	private function requireAndMark(): void {
		$this->passwords->require($this->user->getUID());
		$this->startSession($this->user);
		$this->loginListener()->handle(new UserLoggedInEvent($this->user, $this->user->getUID(), $this->password, false));
		$this->assertNotNull($this->state->get(SessionState::PASSWORD_CHANGE));
	}

	private function loginListener(): PasswordChangeLoginListener {
		$request = $this->createMock(IRequest::class);
		$request->method('getHeader')->willReturnCallback(fn (string $name): string => $this->headers[$name] ?? '');
		return new PasswordChangeLoginListener($this->settings, $this->passwords, $this->state, $request, Server::get(LoggerInterface::class));
	}

	private function controller(): PasswordChangeController {
		$this->sessionUser ??= $this->user;
		return new PasswordChangeController(
			$this->createMock(IRequest::class),
			$this->userSession,
			Server::get(IUserManager::class),
			$this->passwords,
			$this->state,
			Server::get(IURLGenerator::class),
			Server::get(IFactory::class)->get(Application::APP_ID, 'en'),
			Server::get(LocalRedirect::class),
		);
	}

	private function errorOf(\OCP\AppFramework\Http\Response $response): ?string {
		$this->assertInstanceOf(StandaloneTemplateResponse::class, $response);
		$error = $response->getParams()['error'] ?? null;
		return is_string($error) ? $error : null;
	}
}
