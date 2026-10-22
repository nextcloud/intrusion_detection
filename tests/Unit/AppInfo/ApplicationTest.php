<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\AppInfo;

use OC\Core\Events\BeforePasswordResetEvent;
use OC\Core\Events\PasswordResetEvent;
use OCA\DAV\Events\SabrePluginAddEvent;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Config\Lexicon;
use OCA\IntrusionDetection\Dashboard\IntrusionWidget;
use OCA\IntrusionDetection\Event\BanCreatedEvent;
use OCA\IntrusionDetection\Event\BanLiftedEvent;
use OCA\IntrusionDetection\Event\DetectionCreatedEvent;
use OCA\IntrusionDetection\Event\SettingChangedEvent;
use OCA\IntrusionDetection\Event\WasThisYouAnsweredEvent;
use OCA\IntrusionDetection\Guard\AddressGuard;
use OCA\IntrusionDetection\Guard\CredentialUseGuard;
use OCA\IntrusionDetection\Guard\PayloadGuard;
use OCA\IntrusionDetection\Guard\TrapUrlGuard;
use OCA\IntrusionDetection\Guide\SecureAccountNotifier;
use OCA\IntrusionDetection\KnownDevice\IKnownDevices;
use OCA\IntrusionDetection\KnownDevice\KnownDevices;
use OCA\IntrusionDetection\Listener\AdminChangeListener;
use OCA\IntrusionDetection\Listener\AppPasswordCreatedListener;
use OCA\IntrusionDetection\Listener\BlocklistLoginListener;
use OCA\IntrusionDetection\Listener\BreachResetListener;
use OCA\IntrusionDetection\Listener\FailedLoginListener;
use OCA\IntrusionDetection\Listener\FirewallExportListener;
use OCA\IntrusionDetection\Listener\KnownDeviceListener;
use OCA\IntrusionDetection\Listener\LoginFlowGrantedListener;
use OCA\IntrusionDetection\Listener\LoginHistoryListener;
use OCA\IntrusionDetection\Listener\LoginListener;
use OCA\IntrusionDetection\Listener\PasswordUpdatedListener;
use OCA\IntrusionDetection\Listener\ResetRequestedListener;
use OCA\IntrusionDetection\Listener\SabrePluginAddListener;
use OCA\IntrusionDetection\Listener\SecondFactorFailedListener;
use OCA\IntrusionDetection\Listener\SecureGuideListener;
use OCA\IntrusionDetection\Listener\SecurityChangeListener;
use OCA\IntrusionDetection\Listener\ShareAccessFailedListener;
use OCA\IntrusionDetection\Listener\StepUpChallengePassedListener;
use OCA\IntrusionDetection\Listener\TrapNamesChangedListener;
use OCA\IntrusionDetection\Listener\UntrustedSecondFactorListener;
use OCA\IntrusionDetection\Listener\UserDeletedListener;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\Middleware\PayloadMiddleware;
use OCA\IntrusionDetection\Middleware\SessionStateMiddleware;
use OCA\IntrusionDetection\Notification\Notifier;
use OCA\IntrusionDetection\Notification\ShareOwnerNotifier;
use OCA\IntrusionDetection\Response\IAcceptedLogins;
use OCA\IntrusionDetection\SetupCheck\AdminContactCheck;
use OCA\IntrusionDetection\SetupCheck\AdminNetworksCheck;
use OCA\IntrusionDetection\SetupCheck\ApprovalCheck;
use OCA\IntrusionDetection\SetupCheck\BlocklistSyncCheck;
use OCA\IntrusionDetection\SetupCheck\BruteForceProtectionCheck;
use OCA\IntrusionDetection\SetupCheck\LearningModeCheck;
use OCA\IntrusionDetection\SetupCheck\MailCheck;
use OCA\IntrusionDetection\SetupCheck\MemoryCacheCheck;
use OCA\IntrusionDetection\SetupCheck\ReverseProxyCheck;
use OCA\IntrusionDetection\SetupCheck\SharedAddressCheck;
use OCA\IntrusionDetection\SetupCheck\StaleCredentialsCheck;
use OCA\IntrusionDetection\SetupCheck\TrapNameCollisionCheck;
use OCA\IntrusionDetection\SetupCheck\UsersWithoutConfirmationCheck;
use OCA\IntrusionDetection\TrustedNetwork\ITrustedNetworks;
use OCA\IntrusionDetection\TrustedNetwork\TrustedNetworks;
use OCP\App\Events\AppDisableEvent;
use OCP\App\Events\AppEnableEvent;
use OCP\AppFramework\Bootstrap\IRegistrationContext;
use OCP\Authentication\Events\AnyLoginFailedEvent;
use OCP\Authentication\Events\AppPasswordCreatedEvent;
use OCP\Authentication\Events\LoginFlowV2GrantedEvent;
use OCP\Authentication\Events\TokenInvalidatedEvent;
use OCP\Authentication\TwoFactorAuth\TwoFactorProviderChallengeFailed;
use OCP\Authentication\TwoFactorAuth\TwoFactorProviderChallengePassed;
use OCP\Authentication\TwoFactorAuth\TwoFactorProviderForUserRegistered;
use OCP\Authentication\TwoFactorAuth\TwoFactorProviderForUserUnregistered;
use OCP\BeforeSabrePubliclyLoadedEvent;
use OCP\Group\Events\SubAdminAddedEvent;
use OCP\Group\Events\UserAddedEvent;
use OCP\Group\Events\UserRemovedEvent;
use OCP\Security\Events\PasswordResetRequestedEvent;
use OCP\Share\Events\ShareLinkAccessFailedEvent;
use OCP\User\Events\PasswordUpdatedEvent;
use OCP\User\Events\UserChangedEvent;
use OCP\User\Events\UserCreatedEvent;
use OCP\User\Events\UserDeletedEvent;
use OCP\User\Events\UserLoggedInEvent;
use OCP\User\Events\UserLoggedInWithCookieEvent;
use Test\TestCase;

/**
 * What the app registers with core. Guards and global middleware run in
 * registration order, and listeners of one event with the same priority
 * run in registration order too, so the order is part of the behaviour.
 */
class ApplicationTest extends TestCase {
	/** @var array<string, list<mixed>> */
	private array $calls = [];

	protected function setUp(): void {
		parent::setUp();
		$context = $this->createMock(IRegistrationContext::class);
		foreach (['registerConfigLexicon', 'registerRequestGuard', 'registerMiddleware', 'registerEventListener', 'registerNotifierService',
			'registerSetupCheck', 'registerDashboardWidget', 'registerServiceAlias'] as $method) {
			$context->method($method)->willReturnCallback(function (mixed ...$args) use ($method): void {
				$this->calls[$method][] = count($args) === 1 ? $args[0] : $args;
			});
		}
		(new Application())->register($context);
	}

	public function testTheGuardsRunInThisOrder(): void {
		$this->assertSame([AddressGuard::class, TrapUrlGuard::class, PayloadGuard::class, CredentialUseGuard::class], $this->calls['registerRequestGuard']);
	}

	public function testBothMiddlewaresAreGlobalAndThePayloadOneRunsFirst(): void {
		$this->assertSame([[PayloadMiddleware::class, true], [SessionStateMiddleware::class, true]], $this->calls['registerMiddleware']);
	}

	public function testTheListenersOfEachEventRunInThisOrder(): void {
		$byEvent = [];
		foreach ($this->calls['registerEventListener'] as $call) {
			[$event, $listener, $priority] = $call + [2 => 0];
			$byEvent[$event][] = [$listener, $priority];
		}
		ksort($byEvent);
		$expected = [
			AnyLoginFailedEvent::class => [[BlocklistLoginListener::class, 0], [FailedLoginListener::class, 0]],
			AppDisableEvent::class => [[AdminChangeListener::class, -100]],
			AppEnableEvent::class => [[AdminChangeListener::class, -100]],
			AppPasswordCreatedEvent::class => [[AppPasswordCreatedListener::class, 0], [SecurityChangeListener::class, 0]],
			BanCreatedEvent::class => [[FirewallExportListener::class, 0]],
			BanLiftedEvent::class => [[FirewallExportListener::class, 0]],
			BeforePasswordResetEvent::class => [[SecurityChangeListener::class, 0]],
			BeforeSabrePubliclyLoadedEvent::class => [[SabrePluginAddListener::class, 0]],
			DetectionCreatedEvent::class => [[SecureGuideListener::class, 0]],
			LoginFlowV2GrantedEvent::class => [[LoginFlowGrantedListener::class, 0], [SecurityChangeListener::class, 0]],
			PasswordResetEvent::class => [[SecurityChangeListener::class, 0]],
			PasswordResetRequestedEvent::class => [[ResetRequestedListener::class, 0]],
			PasswordUpdatedEvent::class => [
				[BreachResetListener::class, 0],
				[PasswordUpdatedListener::class, 0],
				[KnownDeviceListener::class, 0],
				[SecurityChangeListener::class, 0],
				[SecureGuideListener::class, 0],
			],
			SabrePluginAddEvent::class => [[SabrePluginAddListener::class, 0]],
			SettingChangedEvent::class => [[TrapNamesChangedListener::class, 0], [AdminChangeListener::class, -100]],
			ShareLinkAccessFailedEvent::class => [[ShareAccessFailedListener::class, 0]],
			SubAdminAddedEvent::class => [[AdminChangeListener::class, -100]],
			TokenInvalidatedEvent::class => [[SecurityChangeListener::class, 0]],
			TwoFactorProviderChallengeFailed::class => [[SecondFactorFailedListener::class, 0]],
			TwoFactorProviderChallengePassed::class => [[StepUpChallengePassedListener::class, 0], [LoginHistoryListener::class, 0]],
			TwoFactorProviderForUserRegistered::class => [[UntrustedSecondFactorListener::class, 0], [SecurityChangeListener::class, 0]],
			TwoFactorProviderForUserUnregistered::class => [[UntrustedSecondFactorListener::class, 0], [SecurityChangeListener::class, 0]],
			UserAddedEvent::class => [[AdminChangeListener::class, -100]],
			UserChangedEvent::class => [[SecurityChangeListener::class, 0]],
			UserCreatedEvent::class => [[AdminChangeListener::class, -100]],
			UserDeletedEvent::class => [[UserDeletedListener::class, 0]],
			UserRemovedEvent::class => [[AdminChangeListener::class, -100]],
			UserLoggedInEvent::class => [[LoginListener::class, 10]],
			UserLoggedInWithCookieEvent::class => [[LoginListener::class, 10]],
			WasThisYouAnsweredEvent::class => [[KnownDeviceListener::class, 0], [SecureGuideListener::class, 0]],
		];
		ksort($expected);
		$this->assertSame($expected, $byEvent);
	}

	public function testTheRestIsRegisteredOnce(): void {
		$this->assertSame([Lexicon::class], $this->calls['registerConfigLexicon']);
		$this->assertSame([Notifier::class, ShareOwnerNotifier::class, SecureAccountNotifier::class], $this->calls['registerNotifierService']);
		$this->assertSame([IntrusionWidget::class], $this->calls['registerDashboardWidget']);
		$this->assertSame([[ITrustedNetworks::class, TrustedNetworks::class], [IKnownDevices::class, KnownDevices::class], [IAcceptedLogins::class, LoginHistory::class]], $this->calls['registerServiceAlias']);
		$setupChecks = $this->calls['registerSetupCheck'];
		sort($setupChecks);
		$expected = [
			AdminContactCheck::class, AdminNetworksCheck::class, ApprovalCheck::class, BlocklistSyncCheck::class, BruteForceProtectionCheck::class,
			LearningModeCheck::class, MailCheck::class, MemoryCacheCheck::class, ReverseProxyCheck::class, SharedAddressCheck::class,
			StaleCredentialsCheck::class, TrapNameCollisionCheck::class, UsersWithoutConfirmationCheck::class,
		];
		sort($expected);
		$this->assertSame($expected, $setupChecks);
	}
}
