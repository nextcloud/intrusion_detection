<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\Checks\SecondFactorFailed\SecondFactorFailed;
use OCA\IntrusionDetection\Controller\PersonalApiController;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Guide\SecureAccountGuide;
use OCA\IntrusionDetection\Guide\SecureAccountOverview;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Notification\UserMessages;
use OCA\IntrusionDetection\Personal\FailedLoginStats;
use OCA\IntrusionDetection\Personal\LogOutElsewhere;
use OCA\IntrusionDetection\Personal\PersonalActivity;
use OCA\IntrusionDetection\Personal\PersonalOverview;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\Response\Tokens;
use OCA\IntrusionDetection\Takeover\Db\SecurityChangeMapper;
use OCA\IntrusionDetection\TrustedNetwork\TrustedNetworks;
use OCA\IntrusionDetection\WasThisYou\PersonalDetections;
use OCA\IntrusionDetection\WasThisYou\Questions;
use OCA\IntrusionDetection\WasThisYou\WasThisYouService;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IUser;
use OCP\L10N\IFactory;
use OCP\Log\Audit\CriticalActionPerformedEvent;
use OCP\Notification\IManager as INotificationManager;
use OCP\Server;

/**
 * The personal API wired like the app wires it, with the test session,
 * request and remembered-device cookies, and the audit log captured.
 */
abstract class PersonalApiTestCase extends StepUpTestCase {
	/** @var list<CriticalActionPerformedEvent> */
	protected array $audited = [];
	private \Closure $auditListener;

	protected function setUp(): void {
		parent::setUp();
		$this->auditListener = function (CriticalActionPerformedEvent $e): void {
			$this->audited[] = $e;
		};
		Server::get(IEventDispatcher::class)->addListener(CriticalActionPerformedEvent::class, $this->auditListener);
	}

	protected function tearDown(): void {
		Server::get(IEventDispatcher::class)->removeListener(CriticalActionPerformedEvent::class, $this->auditListener);
		parent::tearDown();
	}

	protected function detection(IUser $user, string $ip): Detection {
		return $this->storeDetection(new DetectionDraft(
			checkId: SecondFactorFailed::ID,
			source: SourceKey::fromIp($ip),
			uid: $user->getUID(),
			userAgent: 'Mozilla/5.0',
		));
	}

	protected function trustedNetwork(IUser $user, string $ip): int {
		Server::get(TrustedNetworks::class)->trust($user->getUID(), SourceKey::fromIp($ip));
		return Server::get(TrustedNetworks::class)->forUser($user->getUID())[0]['id'];
	}

	protected function rememberDevice(IUser $user): int {
		$this->assertTrue($this->knownDevices()->remember($user, SourceKey::fromIp($this->remoteAddress), 'Firefox/131.0 (X11; Linux)'));
		$this->nextRequest();
		$list = $this->knownDevices()->forUser($user->getUID(), Server::get(IFactory::class)->get(Application::APP_ID, 'en'));
		return max(array_column($list, 'id'));
	}

	protected function wasAudited(string $text): bool {
		foreach ($this->audited as $event) {
			if (str_contains($event->getLogMessage(), $text)) {
				return true;
			}
		}
		return false;
	}

	protected function controller(): PersonalApiController {
		$answers = new WasThisYouService(
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
			Server::get(\OCA\IntrusionDetection\Takeover\LockLinks::class),
		);
		$detections = new PersonalDetections(Server::get(DetectionMapper::class), Server::get(UserMessages::class), Server::get(Questions::class), $answers, $this->appSettings(), Server::get(ITimeFactory::class));
		return new PersonalApiController(
			$this->request,
			$this->userSession,
			$detections,
			$answers,
			Server::get(TrustedNetworks::class),
			Server::get(IFactory::class)->get(Application::APP_ID, 'en'),
			$this->knownDevices(),
			Server::get(LoginHistory::class),
			$this->coreSession,
			Server::get(SecureAccountGuide::class),
			Server::get(SecureAccountOverview::class),
			Server::get(SecurityChangeMapper::class),
			$this->appSettings(),
			Server::get(ITimeFactory::class),
			Server::get(PersonalOverview::class),
			new LogOutElsewhere(Server::get(Tokens::class), $this->coreSession, $this->knownDevices(), Server::get(AuditLogger::class)),
			new PersonalActivity(
				Server::get(DetectionMapper::class),
				Server::get(Questions::class),
				$detections,
				Server::get(LoginHistory::class),
				Server::get(SecurityChangeMapper::class),
				Server::get(FailedLoginStats::class),
				Server::get(UserMessages::class),
				$this->coreSession,
				$this->appSettings(),
				Server::get(ITimeFactory::class),
			),
		);
	}
}
