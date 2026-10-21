<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\AccountLocked;
use OCA\IntrusionDetection\Check\Checks\AccountTakeover;
use OCA\IntrusionDetection\Controller\LockLinkController;
use OCA\IntrusionDetection\Controller\SecureAccountAdminController;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Db\LockLinkMapper;
use OCA\IntrusionDetection\Guide\SecureAccountGuide;
use OCA\IntrusionDetection\Notification\AdminAlerts;
use OCA\IntrusionDetection\Takeover\AccountLock;
use OCA\IntrusionDetection\Takeover\LockLinks;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\AnonRateLimit;
use OCP\AppFramework\Http\Attribute\BruteForceProtection;
use OCP\AppFramework\Http\Attribute\NoCSRFRequired;
use OCP\AppFramework\Http\Attribute\PasswordConfirmationRequired;
use OCP\AppFramework\Http\Attribute\PublicPage;
use OCP\AppFramework\OCS\OCSNotFoundException;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Authentication\Events\AppPasswordCreatedEvent;
use OCP\Authentication\Token\IToken;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IGroupManager;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\IUserManager;
use OCP\L10N\IFactory;
use OCP\Security\ISecureRandom;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * Concept sections 11.15 and 18: the lock link. Opening it does nothing,
 * using it locks once, it expires, it is rate limited and throttled, it can
 * only lock, and its token is stored nowhere.
 */
#[Group('DB')]
class LockLinkTest extends TakeoverTestCase {
	private IUser $user;
	private int $linkId;
	private string $token;
	/** @var array{id: int, secret: string} */
	private array $appPassword;

	protected function setUp(): void {
		parent::setUp();
		$this->user = $this->newUser('ids-lock', 'owner@example.com');
		$this->loginAs($this->user, true);
		$this->user->setSystemEMailAddress('attacker@evil.example');
		$this->appPassword = $this->token($this->user, IToken::PERMANENT_TOKEN, 'Attacker sync');
		Server::get(IEventDispatcher::class)->dispatchTyped(new AppPasswordCreatedEvent($this->tokens->getTokenById($this->appPassword['id'])));
		$this->assertCount(1, $this->sentTo, 'The takeover sent the lock link');
		preg_match('#/lock/(\d+)/([A-Za-z0-9]+)$#', (string)$this->sentTo[0][1]->buttonUrl, $match);
		$this->linkId = (int)$match[1];
		$this->token = $match[2];
		// The visitor of the link is not logged in.
		$this->sessionUser = null;
		$this->session->id = 'visitor-session';
	}

	public function testOpeningTheLinkChangesNothing(): void {
		$response = $this->controller()->show($this->linkId, $this->token);
		$this->assertSame(Http::STATUS_OK, $response->getStatus());
		$this->assertSame(LockLinkController::PAGE_CONFIRM, $response->getParams()['mode']);
		$this->assertSame('o***@example.com', $response->getParams()['sentTo']);
		$this->assertSame('no-store', $response->getHeaders()['Cache-Control']);
		$this->assertSame('no-referrer', $response->getHeaders()['Referrer-Policy']);

		$this->assertTrue($this->reloadUser()->isEnabled());
		$this->assertTrue($this->tokenExists($this->appPassword['id']));
		$this->assertNull(Server::get(LockLinkMapper::class)->find($this->linkId)['used_at'] ?? null);
		$this->assertSame([], $this->lockDetections());
	}

	public function testLockingNeedsTheNonceOfTheConfirmationPage(): void {
		$response = $this->controller()->lock($this->linkId, $this->token, 'guessed-nonce');
		$this->assertSame(Http::STATUS_BAD_REQUEST, $response->getStatus());
		$this->assertSame(LockLinkController::PAGE_CONFIRM, $response->getParams()['mode']);
		$this->assertTrue($this->reloadUser()->isEnabled(), 'A post that did not come from the page locks nothing');

		$nonce = (string)$response->getParams()['nonce'];
		$this->assertSame(LockLinkController::PAGE_LOCKED, $this->controller()->lock($this->linkId, $this->token, $nonce)->getParams()['mode']);
	}

	public function testLockingEndsEverythingDisablesTheAccountAndTellsTheAdministrators(): void {
		$controller = $this->controller();
		$nonce = (string)$controller->show($this->linkId, $this->token)->getParams()['nonce'];
		$response = $controller->lock($this->linkId, $this->token, $nonce);

		$this->assertSame(LockLinkController::PAGE_LOCKED, $response->getParams()['mode']);
		$this->assertFalse($this->reloadUser()->isEnabled(), 'The account is disabled');
		$this->assertFalse($this->tokenExists($this->appPassword['id']), 'App passwords are revoked');
		$this->assertSame([], $this->tokens->getTokenByUser($this->user->getUID()), 'Every session ended');

		$detections = $this->lockDetections();
		$this->assertCount(1, $detections);
		$detection = $detections[0];
		$this->assertSame('critical', $detection->getSeverity());
		$this->assertTrue($detection->isEnforced());
		$this->assertSame('198.51.100.20', $detection->getIp(), 'The address the link was used from');
		$facts = $detection->getExplanationData()['facts'];
		$this->assertSame('o***@example.com', $facts['sentTo']);
		$this->assertSame('a***@evil.example', $facts['newAddress']);
		$this->assertTrue($facts[AdminAlerts::FACT_ALL_ADMINS]);
		$this->assertGreaterThanOrEqual(2, $facts['tokensEnded']);

		$admins = Server::get(IGroupManager::class)->get('admin')?->getUsers() ?? [];
		$this->assertNotSame([], $admins);
		foreach ($admins as $admin) {
			$this->assertNotSame([], $this->notificationsFor($admin->getUID(), AdminAlerts::SUBJECT), 'Every administrator is told');
		}
		$headline = $this->adminAlerts()->headline($detection, Server::get(IFactory::class)->get(Application::APP_ID, 'en'));
		$this->assertSame('The account ' . $this->user->getUID() . ' was locked by the owner of its previous email address', $headline);
	}

	public function testALinkWorksOnceAndNeverUnlocks(): void {
		$controller = $this->controller();
		$nonce = (string)$controller->show($this->linkId, $this->token)->getParams()['nonce'];
		$controller->lock($this->linkId, $this->token, $nonce);
		$this->reloadUser()->setEnabled(true);

		$this->assertSame(LockLinkController::PAGE_USED, $controller->show($this->linkId, $this->token)->getParams()['mode']);
		$this->assertSame(LockLinkController::PAGE_USED, $controller->lock($this->linkId, $this->token, $nonce)->getParams()['mode']);
		$this->assertTrue($this->reloadUser()->isEnabled(), 'A used link changes nothing, in either direction');
		$this->assertCount(1, $this->lockDetections());

		$own = array_filter((new \ReflectionClass(LockLinkController::class))->getMethods(\ReflectionMethod::IS_PUBLIC), static fn (\ReflectionMethod $m): bool => $m->class === LockLinkController::class);
		$this->assertSame(['__construct', 'show', 'lock'], array_values(array_map(static fn (\ReflectionMethod $m): string => $m->getName(), $own)), 'The link can only show its page and lock');
	}

	public function testAnExpiredLinkDoesNothing(): void {
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturn(time() + LockLinks::TTL + 1);
		$links = $this->lockLinksAt($time);
		$this->assertSame(LockLinks::EXPIRED, $links->check($this->linkId, $this->token)[0]);

		$controller = $this->controller($links);
		$response = $controller->show($this->linkId, $this->token);
		$this->assertSame(Http::STATUS_GONE, $response->getStatus());
		$this->assertSame(LockLinkController::PAGE_EXPIRED, $response->getParams()['mode']);
		$this->assertTrue($this->reloadUser()->isEnabled());
	}

	public function testWrongLinksAreThrottledAndLookTheSame(): void {
		$controller = $this->controller();
		$wrongToken = $controller->show($this->linkId, strrev($this->token));
		$unknown = $controller->show($this->linkId + 1000, $this->token);
		$garbage = $controller->lock($this->linkId, 'short', 'x');
		foreach ([$wrongToken, $unknown, $garbage] as $response) {
			$this->assertSame(Http::STATUS_NOT_FOUND, $response->getStatus());
			$this->assertSame(LockLinkController::PAGE_INVALID, $response->getParams()['mode']);
			$this->assertTrue($response->isThrottled(), 'Wrong links count like failed logins');
		}
		$this->assertTrue($this->reloadUser()->isEnabled());
	}

	public function testTheRoutesAreRateLimitedAndOnlyTheLockingPostIsCsrfProtected(): void {
		$show = new \ReflectionMethod(LockLinkController::class, 'show');
		$lock = new \ReflectionMethod(LockLinkController::class, 'lock');
		foreach ([$show, $lock] as $method) {
			$this->assertNotSame([], $method->getAttributes(PublicPage::class), $method->getName());
			$this->assertNotSame([], $method->getAttributes(AnonRateLimit::class), $method->getName());
			$this->assertNotSame([], $method->getAttributes(BruteForceProtection::class), $method->getName());
		}
		$this->assertNotSame([], $show->getAttributes(NoCSRFRequired::class), 'Opened from an email; it only reads');
		$this->assertSame([], $lock->getAttributes(NoCSRFRequired::class), 'Locking needs the request token');
	}

	public function testTheTokenIsStoredAndLoggedNowhere(): void {
		$controller = $this->controller();
		$nonce = (string)$controller->show($this->linkId, $this->token)->getParams()['nonce'];
		$controller->lock($this->linkId, $this->token, $nonce);

		$dump = '';
		foreach (IntegrationTestCase::TABLES as $table) {
			$result = $this->db->getQueryBuilder()->select('*')->from($table)->executeQuery();
			$dump .= json_encode($result->fetchAll(), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
			$result->closeCursor();
		}
		$this->assertStringNotContainsString($this->token, $dump);
		$this->assertStringNotContainsString(strtolower($this->token), strtolower($dump));
		$this->assertStringNotContainsString('owner@example.com', $dump, 'The previous address is stored encrypted and masked only');

		foreach (CapturingNotificationApp::$notifications as $notification) {
			$this->assertStringNotContainsString($this->token, json_encode([$notification->getSubjectParameters(), $notification->getMessageParameters(), $notification->getObjectId()], JSON_THROW_ON_ERROR));
		}
		foreach ($this->mailed as [, $mail]) {
			$this->assertStringNotContainsString($this->token, json_encode([$mail->paragraphs, $mail->listItems, $mail->buttonUrl], JSON_THROW_ON_ERROR), 'Only the email to the previous address carries the link');
		}
		$log = (string)file_get_contents((string)Server::get(\OCP\IConfig::class)->getSystemValueString('logfile', Server::get(\OCP\IConfig::class)->getSystemValueString('datadirectory') . '/nextcloud.log'));
		$this->assertStringNotContainsString($this->token, $log);
	}

	public function testAnAdministratorReEnablesTheAccountAndStartsSecureMyAccount(): void {
		$controller = $this->controller();
		$nonce = (string)$controller->show($this->linkId, $this->token)->getParams()['nonce'];
		$controller->lock($this->linkId, $this->token, $nonce);
		$lock = $this->lockDetections()[0];

		$admin = $this->adminController();
		$state = $admin->show($lock->getId())->getData();
		$this->assertTrue($state['lockedByLink']);
		$this->assertTrue($state['canReenable']);
		$this->assertSame(SecureAccountGuide::REASON_DETECTION, $state['progress']['reason'] ?? null, 'The takeover in Protect started the checklist already');

		$data = $admin->reenable($lock->getId())->getData();
		$this->assertTrue($this->reloadUser()->isEnabled());
		$this->assertTrue($data['enabled']);
		$this->assertFalse($data['canReenable']);
		$this->assertTrue($data['progress']['active']);
		$this->assertSame(SecureAccountGuide::REASON_REENABLED, $data['progress']['reason']);
		$this->assertSame($lock->getId(), $data['progress']['detectionId']);
		$this->assertNotSame([], $this->notificationsFor($this->user->getUID(), SecureAccountGuide::NOTIFICATION_SUBJECT), 'The user is invited to the checklist');

		$again = $admin->reenable($lock->getId());
		$this->assertSame(Http::STATUS_BAD_REQUEST, $again->getStatus(), 'An enabled account is not enabled again');
		$this->assertNotSame([], (new \ReflectionMethod(SecureAccountAdminController::class, 'reenable'))->getAttributes(PasswordConfirmationRequired::class));
	}

	public function testOnlyLocksCanBeReEnabledHere(): void {
		$takeover = Server::get(DetectionMapper::class)->findList(new DetectionFilter(checkIds: [AccountTakeover::ID], uid: $this->user->getUID()))[0];
		$this->reloadUser()->setEnabled(false);
		$response = $this->adminController()->reenable($takeover->getId());
		$this->assertSame(Http::STATUS_BAD_REQUEST, $response->getStatus());
		$this->assertSame(AccountLock::NOT_A_LOCK, $response->getData()['reason']);
		$this->assertFalse($this->reloadUser()->isEnabled());

		$this->expectException(OCSNotFoundException::class);
		$this->adminController()->show(999999999);
	}

	private function controller(?LockLinks $links = null): LockLinkController {
		$links ??= $this->lockLinks();
		return new LockLinkController(
			$this->request('198.51.100.20'),
			$links,
			$this->accountLock(),
			$this->session,
			Server::get(ISecureRandom::class),
			Server::get(IURLGenerator::class),
			Server::get(IFactory::class)->get(Application::APP_ID, 'en'),
		);
	}

	private function adminController(): SecureAccountAdminController {
		$admin = $this->newUser('ids-lock-admin');
		$this->sessionUser = $admin;
		return new SecureAccountAdminController(
			$this->request(),
			Server::get(IFactory::class)->get(Application::APP_ID, 'en'),
			$this->userSession,
			Server::get(DetectionMapper::class),
			Server::get(SecureAccountGuide::class),
			$this->accountLock(),
			Server::get(IUserManager::class),
			Server::get(\OCA\IntrusionDetection\Audit\AuditLogger::class),
		);
	}

	private function lockLinksAt(ITimeFactory $time): LockLinks {
		return new LockLinks(
			Server::get(LockLinkMapper::class),
			Server::get(\OCA\IntrusionDetection\Db\SecurityChangeMapper::class),
			Server::get(\OCA\IntrusionDetection\Crypto\Fingerprinter::class),
			Server::get(ISecureRandom::class),
			Server::get(\OCP\Security\ICrypto::class),
			$this->mails,
			Server::get(\OCA\IntrusionDetection\Notification\UserMessages::class),
			Server::get(\OCA\IntrusionDetection\Explain\DateFormatter::class),
			Server::get(IURLGenerator::class),
			Server::get(\OCP\Defaults::class),
			$time,
			Server::get(\Psr\Log\LoggerInterface::class),
		);
	}

	private function reloadUser(): IUser {
		$user = Server::get(IUserManager::class)->get($this->user->getUID());
		$this->assertNotNull($user);
		return $user;
	}

	/**
	 * @return list<Detection>
	 */
	private function lockDetections(): array {
		return Server::get(DetectionMapper::class)->findList(new DetectionFilter(checkIds: [AccountLocked::ID], uid: $this->user->getUID()));
	}

	protected function tearDown(): void {
		$this->sessionUser = null;
		parent::tearDown();
	}

}
