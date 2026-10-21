<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\Checks\StepUpFailed;
use OCA\IntrusionDetection\Controller\ConfirmController;
use OCA\IntrusionDetection\Db\RiskySessionMapper;
use OCA\IntrusionDetection\Http\LocalRedirect;
use OCA\IntrusionDetection\Listener\SensitiveChallengePassedListener;
use OCA\IntrusionDetection\Lockdown\LockdownState;
use OCA\IntrusionDetection\Notification\AdminNotices;
use OCA\IntrusionDetection\Response\Handlers\ConfirmSensitiveHandler;
use OCA\IntrusionDetection\Sensitive\RiskySessions;
use OCA\IntrusionDetection\Sensitive\SensitiveActions;
use OCA\IntrusionDetection\Sensitive\SensitiveConfirmations;
use OCA\IntrusionDetection\Sensitive\SensitiveSession;
use OCA\IntrusionDetection\Sensitive\ShareSize;
use OCA\IntrusionDetection\SessionState\CurrentSession;
use OCA\IntrusionDetection\SessionState\Rules\SensitiveActionRule;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IConfig;
use OCP\IGroupManager;
use OCP\IURLGenerator;
use OCP\IUserManager;
use OCP\L10N\IFactory;
use OCP\Log\Audit\CriticalActionPerformedEvent;
use OCP\Server;
use Psr\Log\LoggerInterface;

/**
 * Sensitive actions and the confirm page, wired like the app wires them,
 * with the test session, a request whose route and parameters the test
 * chooses, and the audit log captured.
 */
abstract class SensitiveTestCase extends StepUpTestCase {
	protected string $route = '';
	/** @var array<string, mixed> */
	protected array $params = [];
	/** @var list<string> */
	protected array $audited = [];
	/** The share sizing the actions use; the real one unless a test sets it */
	protected ?ShareSize $shareSize = null;
	private ?\Closure $auditListener = null;

	protected function setUp(): void {
		parent::setUp();
		$this->request->method('getParam')->willReturnCallback(fn (string $name, mixed $default = null): mixed => $name === '_route' ? $this->route : ($this->params[$name] ?? $default));
		$this->request->method('getServerHost')->willReturn('cloud.example.com');
		$this->auditListener = function (CriticalActionPerformedEvent $event): void {
			$this->audited[] = vsprintf($event->getLogMessage(), $event->getParameters());
		};
		Server::get(IEventDispatcher::class)->addListener(CriticalActionPerformedEvent::class, $this->auditListener);
	}

	protected function tearDown(): void {
		if ($this->auditListener !== null) {
			Server::get(IEventDispatcher::class)->removeListener(CriticalActionPerformedEvent::class, $this->auditListener);
		}
		parent::tearDown();
	}

	protected function riskySessions(): RiskySessions {
		return new RiskySessions(
			$this->settings,
			Server::get(ITimeFactory::class),
			Server::get(IConfig::class),
			new OverridingContainer([CurrentSession::class => $this->currentSession]),
			Server::get(LoggerInterface::class),
		);
	}

	protected function sensitiveSession(): SensitiveSession {
		return new SensitiveSession($this->settings, Server::get(LockdownState::class), $this->riskySessions(), Server::get(IGroupManager::class), Server::get(ITimeFactory::class));
	}

	protected function confirmations(): SensitiveConfirmations {
		return new SensitiveConfirmations(
			$this->state,
			$this->sensitiveSession(),
			$this->policy(),
			$this->engine(),
			Server::get(StepUpFailed::class),
			$this->settings,
			$this->currentSession,
			$this->addresses(),
			$this->userSession,
			Server::get(ITimeFactory::class),
			Server::get(AuditLogger::class),
			Server::get(LoggerInterface::class),
		);
	}

	protected function actions(): SensitiveActions {
		return new SensitiveActions(
			$this->settings,
			$this->sensitiveSession(),
			Server::get(LockdownState::class),
			$this->request,
			Server::get(IURLGenerator::class),
			Server::get(IFactory::class),
			Server::get(IUserManager::class),
			Server::get(AuditLogger::class),
			new OverridingContainer([
				SensitiveConfirmations::class => $this->confirmations(),
				ShareSize::class => $this->shareSize ?? Server::get(ShareSize::class),
				AdminNotices::class => Server::get(AdminNotices::class),
			]),
		);
	}

	protected function sensitiveRule(): SensitiveActionRule {
		return new SensitiveActionRule($this->request, $this->userSession, new OverridingContainer([SensitiveActions::class => $this->actions()]));
	}

	protected function confirmController(): ConfirmController {
		return new ConfirmController(
			$this->request,
			$this->userSession,
			$this->confirmations(),
			$this->sensitiveSession(),
			$this->state,
			Server::get(LockdownState::class),
			$this->codes(),
			$this->policy(),
			$this->settings,
			Server::get(IURLGenerator::class),
			Server::get(LocalRedirect::class),
			Server::get(IFactory::class)->get(Application::APP_ID, 'en'),
			$this->knownDevices(),
			Server::get(ITimeFactory::class),
		);
	}

	protected function challengeListener(): SensitiveChallengePassedListener {
		return new SensitiveChallengePassedListener($this->state, $this->sensitiveSession(), $this->confirmations(), Server::get(LoggerInterface::class));
	}

	protected function handler(): ConfirmSensitiveHandler {
		return new ConfirmSensitiveHandler($this->state, $this->sensitiveSession(), $this->riskySessions(), $this->currentSession, $this->userSession);
	}

	protected function markedRows(): int {
		$qb = $this->db->getQueryBuilder();
		$qb->select($qb->func()->count('*'))->from(RiskySessionMapper::TABLE);
		$result = $qb->executeQuery();
		$count = (int)$result->fetchOne();
		$result->closeCursor();
		return $count;
	}
}
