<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\SecondFactorFailed\SecondFactorFailedDetector;
use OCA\IntrusionDetection\Controller\PasswordChangeController;
use OCA\IntrusionDetection\Db\AttemptMapper;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Db\TokenOriginMapper;
use OCA\IntrusionDetection\Detection\AttemptRecorder;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Guide\SecureAccountGuide;
use OCA\IntrusionDetection\Guide\SecureAccountNotifier;
use OCA\IntrusionDetection\Http\LocalRedirect;
use OCA\IntrusionDetection\Listener\AppPasswordCreatedListener;
use OCA\IntrusionDetection\Listener\Login\PasswordChangeStep;
use OCA\IntrusionDetection\Login\SessionMarkers;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Notification\Notifier;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\Response\PasswordChangeService;
use OCA\IntrusionDetection\Signal\SecondFactorFailure;
use OCA\IntrusionDetection\Tests\LoginSteps;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Authentication\Events\AppPasswordCreatedEvent;
use OCP\Authentication\Token\IToken;
use OCP\IConfig;
use OCP\IRequest;
use OCP\IURLGenerator;
use OCP\IUserManager;
use OCP\L10N\IFactory;
use OCP\Server;
use OCP\User\Events\UserLoggedInEvent;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;

/**
 * Concept section 18 for sessions, app passwords and passwords: a failed
 * second factor that ends a session and its app passwords, and a forced
 * password change, leave no session id, token or password in any table,
 * notification, email, narrative or log line.
 */
#[Group('DB')]
class NoSecretsSessionTest extends AccountTestCase {
	public function testNoTokenOrPasswordReachesAnyTableNotificationEmailOrLog(): void {
		$logFile = $this->logFile();
		$logOffset = is_file($logFile) ? (int)filesize($logFile) : 0;
		$user = $this->newUser('ids-secrets', 'secrets@example.com');
		$oldPassword = 'A-long-test-password-' . $user->getUID();
		$pending = $this->startSession($user);
		$appPassword = $this->token($user, IToken::PERMANENT_TOKEN, 'Created while waiting for the second factor');
		$secrets = [
			'session id' => $pending['secret'],
			'app password' => $appPassword['secret'],
			'old password' => $oldPassword,
			'wrong password' => 'Secret-Wrong-Current-Password-5e5e',
			'new password' => 'Secret-New-Password-Chosen-7a7a',
		];
		$request = $this->createMock(IRequest::class);
		$request->method('getRemoteAddress')->willReturn('198.51.100.7');
		$request->method('getHeader')->willReturn('');
		(new AppPasswordCreatedListener($this->appSettings(), Server::get(TokenOriginMapper::class), $this->coreSession, $request, Server::get(ITimeFactory::class), Server::get(LoggerInterface::class)))
			->handle(new AppPasswordCreatedEvent($this->tokens->getTokenById($appPassword['id'])));

		$dispatcher = $this->dispatcher([SecondFactorFailedDetector::class => new SecondFactorFailedDetector($this->checkSettings(), Server::get(AttemptRecorder::class), Server::get(AttemptMapper::class), Server::get(FlaggedSources::class), $this->coreSession, $this->session, Server::get(LoggerInterface::class))], $this->engine());
		for ($i = 0; $i < 3; $i++) {
			$dispatcher->dispatch(new SecondFactorFailure($user, 'totp', 'TOTP', SourceKey::fromIp('198.51.100.7'), 'Mozilla/5.0 test'));
		}
		$this->assertFalse($this->tokenExists($appPassword['id']), 'The scenario ended the app password');

		// The next login changes the password on the page.
		$this->startSession($user);
		$state = new SessionMarkers($this->session, Server::get(LoggerInterface::class));
		$passwords = Server::get(PasswordChangeService::class);
		LoginSteps::listener([PasswordChangeStep::class => new PasswordChangeStep($passwords, $state)], $this->appSettings(), $request)
			->handle(new UserLoggedInEvent($user, $user->getUID(), $oldPassword, false));
		$controller = new PasswordChangeController($request, $this->userSession, Server::get(IUserManager::class), $passwords, $state, Server::get(IURLGenerator::class), Server::get(IFactory::class)->get(Application::APP_ID, 'en'), Server::get(LocalRedirect::class), Server::get(\OCP\App\IAppManager::class), Server::get(\OCA\IntrusionDetection\Check\Checks\BreachedPassword\NewPasswords::class), Server::get(\OCA\IntrusionDetection\Response\Tokens::class), $this->coreSession);
		$controller->change($secrets['wrong password'], $secrets['new password'], $secrets['new password']);
		$controller->change($oldPassword, $secrets['new password'], $secrets['new password']);
		$this->assertNotFalse(Server::get(IUserManager::class)->checkPassword($user->getUID(), $secrets['new password']), 'The scenario changed the password');

		foreach (IntegrationTestCase::tables() as $table) {
			$result = $this->db->getQueryBuilder()->select('*')->from($table)->executeQuery();
			$this->assertClean(json_encode($result->fetchAll(), JSON_THROW_ON_ERROR), $secrets, $table);
			$result->closeCursor();
		}
		$this->assertNotSame([], CapturingNotificationApp::$notifications);
		foreach (CapturingNotificationApp::$notifications as $notification) {
			$notifier = $notification->getSubject() === SecureAccountGuide::NOTIFICATION_SUBJECT ? Server::get(SecureAccountNotifier::class) : Server::get(Notifier::class);
			$prepared = $notifier->prepare($notification, 'en');
			$this->assertClean(json_encode($notification->getSubjectParameters()) . $prepared->getParsedSubject() . $prepared->getParsedMessage() . $prepared->getLink(), $secrets, 'notification');
		}
		$this->assertNotSame([], $this->queuedMails());
		$this->assertClean(json_encode($this->queuedMails(), JSON_THROW_ON_ERROR), $secrets, 'queued emails');
		$this->sendQueuedMails();
		$this->assertNotSame([], $this->mailed);
		foreach ($this->mailed as [, $mail]) {
			$this->assertClean(json_encode(get_object_vars($mail), JSON_THROW_ON_ERROR), $secrets, 'email');
		}
		$l = Server::get(IFactory::class)->get(Application::APP_ID, 'en');
		foreach (Server::get(DetectionMapper::class)->findList(new DetectionFilter()) as $detection) {
			$this->assertClean(json_encode(Server::get(NarrativeBuilder::class)->build($detection, $l)->toArray()), $secrets, 'narrative');
		}
		$this->assertClean(json_encode($this->session->get(SessionMarkers::SESSION_KEY)), $secrets, 'session state');
		$this->assertClean(is_file($logFile) ? (string)file_get_contents($logFile, false, null, $logOffset) : '', $secrets, 'server log');
	}

	/**
	 * @param array<string, string> $secrets
	 */
	private function assertClean(string $text, array $secrets, string $where): void {
		foreach ($secrets as $name => $secret) {
			$this->assertStringNotContainsString($secret, $text, 'The ' . $name . ' is in the ' . $where);
		}
	}

	private function logFile(): string {
		$config = Server::get(IConfig::class);
		return $config->getSystemValueString('logfile', $config->getSystemValueString('datadirectory', \OC::$SERVERROOT . '/data') . '/nextcloud.log');
	}
}
