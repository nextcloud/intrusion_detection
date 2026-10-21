<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\Authentication\TwoFactorAuth\ProviderLoader;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\SecondFactorFailed;
use OCA\IntrusionDetection\Check\Checks\TokenConcurrentUse;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Controller\PersonalApiController;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\LoginHistoryMapper;
use OCA\IntrusionDetection\Db\SecurityChangeMapper;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Detection\DetectionService;
use OCA\IntrusionDetection\Event\DetectionCreatedEvent;
use OCA\IntrusionDetection\Event\WasThisYouAnsweredEvent;
use OCA\IntrusionDetection\Guide\SecureAccountGuide;
use OCA\IntrusionDetection\Guide\SecureAccountNotifier;
use OCA\IntrusionDetection\Guide\SecureAccountOverview;
use OCA\IntrusionDetection\KnownDevice\KnownDevices;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Notification\AdminLinks;
use OCA\IntrusionDetection\Personal\LogOutElsewhere;
use OCA\IntrusionDetection\Personal\PersonalOverview;
use OCA\IntrusionDetection\TrustedNetwork\TrustedNetworks;
use OCA\IntrusionDetection\WasThisYou\PersonalDetections;
use OCA\IntrusionDetection\WasThisYou\WasThisYouService;
use OCP\AppFramework\Http;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Authentication\TwoFactorAuth\IProvider;
use OCP\Authentication\TwoFactorAuth\IRegistry;
use OCP\Config\IUserConfig;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IRequest;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\IUserManager;
use OCP\L10N\IFactory;
use OCP\Notification\AlreadyProcessedException;
use OCP\Notification\IManager as INotificationManager;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;

/**
 * Concept section 15.3 and the tests of section 20: what starts the
 * checklist, how each step is done, a password managed elsewhere, no
 * second factor available, and the personal endpoints.
 */
#[Group('DB')]
class SecureAccountGuideTest extends AccountTestCase {
	private SecureAccountGuide $guide;

	protected function setUp(): void {
		parent::setUp();
		$this->guide = Server::get(SecureAccountGuide::class);
	}

	public function testNoItWasNotMeStartsIt(): void {
		$user = $this->newUser('ids-guide');
		$detection = $this->detection($user, TokenConcurrentUse::ID, true);
		Server::get(IEventDispatcher::class)->dispatchTyped(new WasThisYouAnsweredEvent($detection, Detection::VERDICT_DENIED));

		$state = $this->guide->state($user->getUID());
		$this->assertNotNull($state);
		$this->assertSame(SecureAccountGuide::REASON_DENIED, $state['reason']);
		$this->assertSame($detection->getId(), $state['detection']);
		$this->assertCount(1, $this->notificationsFor($user->getUID(), SecureAccountGuide::NOTIFICATION_SUBJECT));
	}

	public function testYesItWasMeDoesNotStartIt(): void {
		$user = $this->newUser('ids-guide');
		Server::get(IEventDispatcher::class)->dispatchTyped(new WasThisYouAnsweredEvent($this->detection($user, TokenConcurrentUse::ID, true), Detection::VERDICT_CONFIRMED));
		$this->assertNull($this->guide->state($user->getUID()));
	}

	public function testOnlyActingChecksThatMeanAStolenPasswordStartIt(): void {
		$user = $this->newUser('ids-guide');
		$dispatcher = Server::get(IEventDispatcher::class);
		$dispatcher->dispatchTyped(new DetectionCreatedEvent($this->detection($user, SecondFactorFailed::ID, false)));
		$this->assertNull($this->guide->state($user->getUID()), 'An observed detection starts nothing');
		$dispatcher->dispatchTyped(new DetectionCreatedEvent($this->detection($user, TokenConcurrentUse::ID, true)));
		$this->assertNull($this->guide->state($user->getUID()), 'Not every check starts it');
		$dispatcher->dispatchTyped(new DetectionCreatedEvent($this->detection($user, SecondFactorFailed::ID, true)));
		$this->assertSame(SecureAccountGuide::REASON_DETECTION, $this->guide->state($user->getUID())['reason'] ?? null);
	}

	public function testStepsAreDoneTheirWayAndTheChecklistClosesWhenComplete(): void {
		$user = $this->newUser('ids-guide');
		$this->guide->start($user->getUID(), SecureAccountGuide::REASON_SELF);
		$this->assertSame([], $this->notificationsFor($user->getUID(), SecureAccountGuide::NOTIFICATION_SUBJECT), 'Started by the user: no notification');
		$progress = $this->guide->progress($user);
		$this->assertTrue($progress['active']);
		$this->assertSame(0, $progress['done']);
		$this->assertSame(5, $progress['total'], 'No second factor is available here, so that step is left out');
		$this->assertTrue($this->step($progress, 'two_factor')['skipped']);

		$user->setPassword('A-new-test-password-for-the-guide');
		$this->assertTrue($this->step($this->guide->progress($user), 'password')['done'], 'A new password set after the start');

		foreach (SecureAccountGuide::USER_STEPS as $step) {
			$this->assertTrue($this->guide->markDone($user->getUID(), $step));
		}
		$progress = $this->guide->progress($user);
		$this->assertFalse($progress['active']);
		$this->assertSame(SecureAccountGuide::CLOSED_DONE, $progress['closedBy']);
		$this->assertSame(5, $progress['done']);
		$this->assertFalse($this->guide->markDone($user->getUID(), SecureAccountGuide::STEP_FILES), 'A closed checklist takes no more steps');
	}

	public function testASecondFactorCountsWhenOneIsAvailable(): void {
		$user = $this->newUser('ids-guide');
		$provider = $this->createMock(IProvider::class);
		$provider->method('getId')->willReturn('ids_totp');
		$loader = $this->createMock(ProviderLoader::class);
		$loader->method('getProviders')->willReturn(['ids_totp' => $provider]);
		$guide = new SecureAccountGuide(Server::get(IUserConfig::class), Server::get(IUserManager::class), Server::get(IRegistry::class), $loader, Server::get(INotificationManager::class), Server::get(ITimeFactory::class), Server::get(LoggerInterface::class));
		$guide->start($user->getUID(), SecureAccountGuide::REASON_SELF);
		$this->assertFalse($this->step($guide->progress($user), 'two_factor')['skipped']);
		$this->assertFalse($this->step($guide->progress($user), 'two_factor')['done']);
		Server::get(IRegistry::class)->enableProviderFor($provider, $user);
		try {
			$this->assertTrue($this->step($guide->progress($user), 'two_factor')['done']);
			$this->assertSame(6, $guide->progress($user)['total']);
		} finally {
			Server::get(IRegistry::class)->cleanUp('ids_totp');
		}
	}

	public function testAPasswordManagedElsewhereWaitsForTheAdministrator(): void {
		$user = $this->newUser('ids-guide');
		$external = $this->createMock(IUser::class);
		$external->method('getUID')->willReturn($user->getUID());
		$external->method('canChangePassword')->willReturn(false);
		$this->guide->start($user->getUID(), SecureAccountGuide::REASON_SELF);
		$this->assertTrue($this->step($this->guide->progress($external), 'password')['managed']);
	}

	public function testDismissing(): void {
		$user = $this->newUser('ids-guide');
		$this->guide->start($user->getUID(), SecureAccountGuide::REASON_DENIED);
		$notifier = new SecureAccountNotifier(Server::get(IFactory::class), $this->guide, Server::get(IURLGenerator::class), Server::get(AdminLinks::class));
		$notification = $this->notificationsFor($user->getUID(), SecureAccountGuide::NOTIFICATION_SUBJECT)[0];
		$prepared = $notifier->prepare($notification, 'en');
		$this->assertSame('Secure your account', $prepared->getParsedSubject());
		$this->assertStringContainsString('/apps/intrusion_detection/secure-account', $prepared->getLink());

		$this->assertTrue($this->guide->dismiss($user->getUID()));
		$this->assertSame(SecureAccountGuide::CLOSED_DISMISSED, $this->guide->progress($user)['closedBy']);
		$this->expectException(AlreadyProcessedException::class);
		$notifier->prepare($notification, 'en');
	}

	public function testThePersonalEndpointsOnlyTouchTheOwnAccount(): void {
		$user = $this->newUser('ids-guide', 'owner@example.com');
		$other = $this->newUser('ids-guide-other');
		$mapper = Server::get(SecurityChangeMapper::class);
		foreach ([$user, $other] as $account) {
			$mapper->insert(['uid' => $account->getUID(), 'type' => 'password_changed', 'via' => 'self', 'actor_uid' => $account->getUID(), 'old_value_hint' => null, 'new_value_hint' => null, 'notify_to' => null, 'ref_id' => null, 'detail' => null, 'session_token_id' => null, 'ip' => '203.0.113.9', 'created_at' => time()]);
		}
		$this->startSession($user);
		$controller = $this->controller();

		$changes = $controller->securityChanges(500)->getData();
		$this->assertNotSame([], $changes);
		$this->assertCount(1, array_filter($changes, static fn (array $c): bool => $c['address'] === '203.0.113.9'), 'Only the own account\'s changes');

		$this->assertSame(Http::STATUS_CONFLICT, $controller->completeSecureAccountStep('sessions')->getStatus(), 'Nothing is open');
		$started = $controller->startSecureAccount()->getData();
		$this->assertTrue($started['progress']['active']);
		$this->assertSame('owner@example.com', $started['email']);
		$this->assertSame(Http::STATUS_BAD_REQUEST, $controller->completeSecureAccountStep('password')->getStatus(), 'The password step is done by a new password');
		$this->assertSame(Http::STATUS_BAD_REQUEST, $controller->completeSecureAccountStep('two_factor')->getStatus());
		$done = $controller->completeSecureAccountStep('sessions')->getData();
		$this->assertTrue($this->step($done['progress'], 'sessions')['done']);
		$this->assertNull($this->guide->state($other->getUID()), 'The other account is untouched');
		$this->assertFalse($controller->dismissSecureAccount()->getData()['progress']['active']);
	}

	/**
	 * @param array{steps: list<array{id: string, done: bool, doneAt: ?int, skipped: bool, managed: bool, userConfirms: bool}>} $progress
	 * @return array{id: string, done: bool, doneAt: ?int, skipped: bool, managed: bool, userConfirms: bool}
	 */
	private function step(array $progress, string $id): array {
		foreach ($progress['steps'] as $step) {
			if ($step['id'] === $id) {
				return $step;
			}
		}
		$this->fail('No step ' . $id);
	}

	private function detection(IUser $user, string $checkId, bool $enforced): Detection {
		$mode = $enforced ? Mode::Protect : Mode::Observe;
		[$detection] = Server::get(DetectionService::class)->record(new DetectionDraft($checkId, SourceKey::fromIp('203.0.113.5'), $user->getUID(), []), new ModeState($mode, $mode));
		return $detection;
	}

	private function controller(): PersonalApiController {
		return new PersonalApiController(
			$this->createMock(IRequest::class),
			$this->userSession,
			Server::get(PersonalDetections::class),
			Server::get(WasThisYouService::class),
			Server::get(TrustedNetworks::class),
			Server::get(IFactory::class)->get(Application::APP_ID, 'en'),
			Server::get(KnownDevices::class),
			Server::get(LoginHistoryMapper::class),
			$this->currentSession,
			$this->guide,
			new SecureAccountOverview($this->guide, Server::get(SecurityChangeMapper::class), Server::get(\OCA\IntrusionDetection\Db\TokenOriginMapper::class), $this->tokens, $this->currentSession, Server::get(\OCP\Share\IManager::class), Server::get(\OCP\App\IAppManager::class), Server::get(IURLGenerator::class), Server::get(ITimeFactory::class), Server::get(LoggerInterface::class)),
			Server::get(SecurityChangeMapper::class),
			$this->settings,
			Server::get(ITimeFactory::class),
			Server::get(PersonalOverview::class),
			Server::get(LogOutElsewhere::class),
		);
	}
}
