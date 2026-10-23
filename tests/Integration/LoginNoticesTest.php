<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\Core\Controller\LoginController;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\Checks\StepUpRefused\StepUpRefused;
use OCA\IntrusionDetection\Config\UserKeys;
use OCA\IntrusionDetection\Confirm\IConfirmationMethod;
use OCA\IntrusionDetection\Controller\NoticeController;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Http\LocalRedirect;
use OCA\IntrusionDetection\KnownDevice\Db\KnownDeviceMapper;
use OCA\IntrusionDetection\Login\SessionMarkers;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Notification\AdminNotices;
use OCA\IntrusionDetection\Notification\LoginNotices;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\SessionState\RequestTarget;
use OCA\IntrusionDetection\SessionState\Rules\LoginNoticeRule;
use OCA\IntrusionDetection\TrustedNetwork\TrustedNetworks;
use OCA\IntrusionDetection\WasThisYou\PersonalDetections;
use OCA\IntrusionDetection\WasThisYou\Questions;
use OCA\IntrusionDetection\WasThisYou\WasThisYouService;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\Http\StandaloneTemplateResponse;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Config\IUserConfig;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\L10N\IFactory;
use OCP\Notification\IManager as INotificationManager;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * Users Nextcloud cannot reach by email (concept section 11.1): besides the
 * notification, the event is shown once at their next login from a known
 * device, before the start page, and the administrators learn about severe
 * ones.
 */
#[Group('DB')]
class LoginNoticesTest extends StepUpTestCase {
	private IUser $bob;

	protected function setUp(): void {
		parent::setUp();
		$this->bob = $this->user('ids-notice', null);
		Server::get(FlaggedSources::class)->flagSource(SourceKey::fromIp($this->remoteAddress), FlaggedSources::REASON_ATTACK);
	}

	public function testAnEventTheUserCouldOnlyBeToldInsideNextcloudIsRemembered(): void {
		$this->refusedLogin();
		$since = $this->notices()->since($this->bob->getUID());
		$this->assertNotNull($since, 'No email address: remembered for the next login');
		$detection = $this->detectionsOf(StepUpRefused::ID)[0];
		$this->assertSame($detection->getCreatedAt(), $since);
		$this->assertNotSame([], $this->notificationsFor($this->bob->getUID()), 'The notification as for everyone');

		$this->assertTrue(Server::get(IUserConfig::class)->hasKey($this->bob->getUID(), Application::APP_ID, UserKeys::LOGIN_NOTICE_SINCE));
		$this->notices()->remember($this->bob->getUID(), $since + 100);
		$this->assertSame($since, $this->notices()->since($this->bob->getUID()), 'The oldest one is kept');
	}

	public function testTheNoticeIsShownAtTheNextLoginFromAKnownDeviceOrWhenThereIsNone(): void {
		$this->refusedLogin();
		$this->session->clear();
		$this->notices()->atLogin($this->bob->getUID(), null);
		$this->assertNotNull($this->state->get(SessionMarkers::LOGIN_NOTICE), 'Without any known device: the next login');

		$this->session->clear();
		Server::get(KnownDeviceMapper::class)->insert($this->bob->getUID(), str_repeat('a', 64), 'firefox', 'linux', 'Firefox on Linux', null, time());
		$this->notices()->atLogin($this->bob->getUID(), null);
		$this->assertNull($this->state->get(SessionMarkers::LOGIN_NOTICE), 'Not on a device the user never confirmed: it may be the attacker');

		$device = Server::get(KnownDeviceMapper::class)->find($this->bob->getUID(), str_repeat('a', 64), 0);
		$this->notices()->atLogin($this->bob->getUID(), $device);
		$this->assertNotNull($this->state->get(SessionMarkers::LOGIN_NOTICE), 'On a known device');
	}

	public function testOnlyPageNavigationsAreSentToTheNotice(): void {
		$this->state->set(SessionMarkers::LOGIN_NOTICE, ['uid' => $this->bob->getUID(), 'since' => 1]);
		$page = $this->createMock(Controller::class);
		$this->headers['Accept'] = 'text/html,application/xhtml+xml';
		$this->method = 'GET';
		$block = $this->noticeRule()->check($this->state, RequestTarget::app($page, 'index', 'GET', '/index.php/apps/files/'));
		$this->assertNotNull($block);
		$this->assertStringContainsString('/apps/intrusion_detection/notice', (string)$block->redirectUrl);

		$this->assertNull($this->noticeRule()->check($this->state, RequestTarget::app($page, 'index', 'POST', '/index.php/apps/files/')), 'Writes are never held up');
		$this->assertNull($this->noticeRule()->check($this->state, RequestTarget::dav('GET', '/remote.php/dav/files/bob')), 'Neither is WebDAV');
		$this->assertNull($this->noticeRule()->check($this->state, RequestTarget::app($this->createMock(LoginController::class), 'logout', 'GET', '/index.php/logout')), 'Logging out works');
		$this->headers['Accept'] = 'application/json';
		$this->assertNull($this->noticeRule()->check($this->state, RequestTarget::app($page, 'index', 'GET', '/index.php/apps/files/api')), 'Nor are scripts');
	}

	public function testThePageShowsTheEventsAndContinuingClearsThem(): void {
		$this->refusedLogin();
		$this->startSession($this->bob);
		$this->notices()->atLogin($this->bob->getUID(), null);

		$page = $this->controller()->show('/index.php/apps/files/');
		$this->assertInstanceOf(StandaloneTemplateResponse::class, $page);
		$html = $page->render();
		$this->assertStringContainsString('A login to your account was refused', $html);
		$this->assertStringContainsString('No, it was not me', $html);
		$this->assertStringContainsString('Yes, it was me', $html, 'Both answers are offered, as in the email');
		$this->assertLessThan(strpos($html, 'No, it was not me'), strpos($html, 'Yes, it was me'));
		$this->assertStringContainsString('&quot;Yes&quot; needs a login with your second factor', $html, 'This login proved only the password');
		$this->assertStringContainsString('Add an email address', $html);

		$response = $this->controller()->done('/index.php/apps/files/');
		$this->assertInstanceOf(RedirectResponse::class, $response);
		$this->assertStringEndsWith('/index.php/apps/files/', $response->getRedirectURL());
		$this->assertNull($this->notices()->since($this->bob->getUID()));
		$this->assertNull($this->state->get(SessionMarkers::LOGIN_NOTICE));
		$this->assertInstanceOf(RedirectResponse::class, $this->controller()->show(), 'Nothing left to show');
	}

	public function testNoItWasNotMeCanBeAnsweredOnThePage(): void {
		$this->refusedLogin();
		$this->session->clear();
		$this->startSession($this->bob);
		$this->sessionConfirmation()->proved($this->bob->getUID(), IConfirmationMethod::KNOWN_DEVICE);
		$this->notices()->atLogin($this->bob->getUID(), null);
		$detection = $this->detectionsOf(StepUpRefused::ID)[0];
		$response = $this->controller()->deny($detection->getId());
		$this->assertInstanceOf(StandaloneTemplateResponse::class, $response);
		$this->assertSame('denied', Server::get(DetectionMapper::class)->findById($detection->getId())->getUserVerdict());
		$html = $response->render();
		$this->assertStringContainsString('You answered: No, it was not me.', $html);
		$this->assertStringContainsString('Your answer was recorded and your administrator was told.', $html);
	}

	public function testNoAfterALoginWithOnlyThePasswordTellsHowToAnswerSoThatItCounts(): void {
		$this->refusedLogin();
		$this->session->clear();
		$this->startSession($this->bob);
		$this->notices()->atLogin($this->bob->getUID(), null);
		$detection = $this->detectionsOf(StepUpRefused::ID)[0];
		$response = $this->controller()->deny($detection->getId());
		$this->assertInstanceOf(StandaloneTemplateResponse::class, $response);
		$this->assertNull(Server::get(DetectionMapper::class)->findById($detection->getId())->getUserVerdict(), 'The question stays open');
		$this->assertStringContainsString('Your administrator was told. To end the sessions of this event, answer again after a login with your second factor', $response->render());
	}

	public function testAdministratorsLearnWhomTheyCannotReach(): void {
		$this->refusedLogin();
		$detection = $this->detectionsOf(StepUpRefused::ID)[0];
		$detection->setSeverity('high');
		// A new hour: the earlier notice about the refusal does not hold this one back.
		$this->db->getQueryBuilder()->delete('ids_alerts')->executeStatement();
		$this->assertSame(1, $this->userAlerts()->notify($detection)['admins'] ?? null, 'For severe events, the administrators are told');
		$this->assertNotSame([], $this->notificationsFor('admin', AdminNotices::SUBJECT_USER_UNREACHABLE));
	}

	private function refusedLogin(): void {
		$this->startSession($this->bob);
		$this->login($this->bob);
		$this->assertCount(1, $this->detectionsOf(StepUpRefused::ID));
	}

	private function notices(): LoginNotices {
		return new LoginNotices(Server::get(IUserConfig::class), $this->state, Server::get(KnownDeviceMapper::class), Server::get(ITimeFactory::class));
	}

	private function noticeRule(): LoginNoticeRule {
		return new LoginNoticeRule($this->request, Server::get(IURLGenerator::class));
	}

	private function controller(): NoticeController {
		$request = $this->request;
		return new NoticeController(
			$request,
			$this->userSession,
			$this->notices(),
			Server::get(PersonalDetections::class),
			new WasThisYouService(
				Server::get(DetectionMapper::class),
				Server::get(Questions::class),
				$this->engine(),
				$this->appSettings(), $this->checkSettings(),
				Server::get(FlaggedSources::class),
				Server::get(TrustedNetworks::class),
				$this->sessionKiller(),
				$this->coreSession,
				$this->addresses(),
				$this->sessionConfirmation(),
				Server::get(INotificationManager::class),
				Server::get(IEventDispatcher::class),
				Server::get(AuditLogger::class),
				Server::get(ITimeFactory::class),
			),
			Server::get(IURLGenerator::class),
			Server::get(LocalRedirect::class),
			Server::get(IFactory::class)->get(Application::APP_ID, 'en'),
		);
	}
}
