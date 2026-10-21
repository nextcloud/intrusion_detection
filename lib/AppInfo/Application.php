<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\AppInfo;

use OC\Core\Events\BeforePasswordResetEvent;
use OC\Core\Events\PasswordResetEvent;
use OCA\DAV\Events\SabrePluginAddEvent;
use OCA\IntrusionDetection\Admin\SetupProblems;
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
use OCA\IntrusionDetection\Listener\BreachedPasswordListener;
use OCA\IntrusionDetection\Listener\BreachResetListener;
use OCA\IntrusionDetection\Listener\CredentialUseLoginListener;
use OCA\IntrusionDetection\Listener\FailedLoginListener;
use OCA\IntrusionDetection\Listener\FirewallExportListener;
use OCA\IntrusionDetection\Listener\KnownDeviceListener;
use OCA\IntrusionDetection\Listener\LoginFlowGrantedListener;
use OCA\IntrusionDetection\Listener\LoginHistoryListener;
use OCA\IntrusionDetection\Listener\LoginRecordListener;
use OCA\IntrusionDetection\Listener\PasswordChangeLoginListener;
use OCA\IntrusionDetection\Listener\PasswordUpdatedListener;
use OCA\IntrusionDetection\Listener\PayloadLoginListener;
use OCA\IntrusionDetection\Listener\ResetRequestedListener;
use OCA\IntrusionDetection\Listener\SabrePluginAddListener;
use OCA\IntrusionDetection\Listener\SecondFactorFailedListener;
use OCA\IntrusionDetection\Listener\SecureGuideListener;
use OCA\IntrusionDetection\Listener\SecurityChangeListener;
use OCA\IntrusionDetection\Listener\ShareAccessFailedListener;
use OCA\IntrusionDetection\Listener\StepUpChallengePassedListener;
use OCA\IntrusionDetection\Listener\StepUpLoginListener;
use OCA\IntrusionDetection\Listener\UntrustedSecondFactorListener;
use OCA\IntrusionDetection\Listener\UserDeletedListener;
use OCA\IntrusionDetection\Middleware\PayloadMiddleware;
use OCA\IntrusionDetection\Middleware\SessionStateMiddleware;
use OCA\IntrusionDetection\Notification\Notifier;
use OCA\IntrusionDetection\Notification\ShareOwnerNotifier;
use OCA\IntrusionDetection\SetupCheck\ApprovalCheck;
use OCA\IntrusionDetection\SetupCheck\BlocklistSyncCheck;
use OCA\IntrusionDetection\TrustedNetwork\ITrustedNetworks;
use OCA\IntrusionDetection\TrustedNetwork\TrustedNetworks;
use OCP\App\Events\AppDisableEvent;
use OCP\App\Events\AppEnableEvent;
use OCP\AppFramework\App;
use OCP\AppFramework\Bootstrap\IBootContext;
use OCP\AppFramework\Bootstrap\IBootstrap;
use OCP\AppFramework\Bootstrap\IRegistrationContext;
use OCP\Authentication\Events\AnyLoginFailedEvent;
use OCP\Authentication\Events\AppPasswordCreatedEvent;
use OCP\Authentication\Events\LoginFlowV2GrantedEvent;
use OCP\Authentication\Events\TokenInvalidatedEvent;
use OCP\Authentication\TwoFactorAuth\TwoFactorProviderChallengeFailed;
use OCP\Authentication\TwoFactorAuth\TwoFactorProviderChallengePassed;
use OCP\Authentication\TwoFactorAuth\TwoFactorProviderForUserRegistered;
use OCP\Authentication\TwoFactorAuth\TwoFactorProviderForUserUnregistered;
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

class Application extends App implements IBootstrap {
	public const APP_ID = 'intrusion_detection';

	public function __construct(array $urlParams = []) {
		parent::__construct(self::APP_ID, $urlParams);
	}

	#[\Override]
	public function register(IRegistrationContext $context): void {
		$context->registerConfigLexicon(Lexicon::class);

		// Request guards run in registration order, on every web request.
		$context->registerRequestGuard(AddressGuard::class);

		$context->registerEventListener(UserLoggedInEvent::class, LoginRecordListener::class);

		$context->registerEventListener(BanCreatedEvent::class, FirewallExportListener::class);
		$context->registerEventListener(BanLiftedEvent::class, FirewallExportListener::class);
		$context->registerEventListener(AnyLoginFailedEvent::class, BlocklistLoginListener::class);
		$context->registerSetupCheck(BlocklistSyncCheck::class);
		$context->registerRequestGuard(TrapUrlGuard::class);
		$context->registerEventListener(AnyLoginFailedEvent::class, FailedLoginListener::class);
		$context->registerNotifierService(Notifier::class);
		$context->registerRequestGuard(PayloadGuard::class);
		$context->registerEventListener(UserLoggedInEvent::class, PayloadLoginListener::class);
		$context->registerMiddleware(PayloadMiddleware::class, true);
		$context->registerDashboardWidget(IntrusionWidget::class);
		$context->registerServiceAlias(ITrustedNetworks::class, TrustedNetworks::class);
		$context->registerEventListener(ShareLinkAccessFailedEvent::class, ShareAccessFailedListener::class);
		$context->registerEventListener(PasswordResetRequestedEvent::class, ResetRequestedListener::class);
		$context->registerEventListener(LoginFlowV2GrantedEvent::class, LoginFlowGrantedListener::class);
		$context->registerNotifierService(ShareOwnerNotifier::class);
		$context->registerEventListener(UserLoggedInEvent::class, BreachedPasswordListener::class);
		$context->registerEventListener(PasswordUpdatedEvent::class, BreachResetListener::class);
		$context->registerEventListener(TwoFactorProviderChallengeFailed::class, SecondFactorFailedListener::class);
		$context->registerEventListener(AppPasswordCreatedEvent::class, AppPasswordCreatedListener::class);
		$context->registerEventListener(UserLoggedInEvent::class, PasswordChangeLoginListener::class);
		$context->registerEventListener(UserLoggedInWithCookieEvent::class, PasswordChangeLoginListener::class);
		$context->registerEventListener(PasswordUpdatedEvent::class, PasswordUpdatedListener::class);
		$context->registerEventListener(UserDeletedEvent::class, UserDeletedListener::class);
		$context->registerEventListener(SabrePluginAddEvent::class, SabrePluginAddListener::class);
		// Global, so that it covers every app's controllers; it runs after core's two-factor middleware.
		$context->registerMiddleware(SessionStateMiddleware::class, true);
		foreach ([UserAddedEvent::class, UserRemovedEvent::class, SubAdminAddedEvent::class, UserCreatedEvent::class, AppEnableEvent::class, AppDisableEvent::class, SettingChangedEvent::class] as $event) {
			$context->registerEventListener($event, AdminChangeListener::class, AdminChangeListener::PRIORITY);
		}
		$context->registerSetupCheck(ApprovalCheck::class);
		foreach (SetupProblems::CHECKS as $setupCheck) {
			$context->registerSetupCheck($setupCheck);
		}
		$context->registerRequestGuard(CredentialUseGuard::class);
		$context->registerEventListener(UserLoggedInEvent::class, CredentialUseLoginListener::class);
		$context->registerServiceAlias(IKnownDevices::class, KnownDevices::class);
		// Before the other login listeners, so that a new password required here is asked for at once.
		$context->registerEventListener(UserLoggedInEvent::class, StepUpLoginListener::class, StepUpLoginListener::PRIORITY);
		$context->registerEventListener(UserLoggedInWithCookieEvent::class, StepUpLoginListener::class, StepUpLoginListener::PRIORITY);
		$context->registerEventListener(TwoFactorProviderChallengePassed::class, StepUpChallengePassedListener::class);
		$context->registerEventListener(TwoFactorProviderForUserRegistered::class, UntrustedSecondFactorListener::class);
		$context->registerEventListener(TwoFactorProviderForUserUnregistered::class, UntrustedSecondFactorListener::class);
		// After the step-up listener, so that the history says how the login was confirmed.
		$context->registerEventListener(UserLoggedInEvent::class, LoginHistoryListener::class);
		$context->registerEventListener(UserLoggedInWithCookieEvent::class, LoginHistoryListener::class);
		$context->registerEventListener(TwoFactorProviderChallengePassed::class, LoginHistoryListener::class);
		$context->registerEventListener(WasThisYouAnsweredEvent::class, KnownDeviceListener::class);
		$context->registerEventListener(PasswordUpdatedEvent::class, KnownDeviceListener::class);
		foreach ([BeforePasswordResetEvent::class, PasswordResetEvent::class, UserChangedEvent::class, PasswordUpdatedEvent::class, TwoFactorProviderForUserRegistered::class, TwoFactorProviderForUserUnregistered::class, AppPasswordCreatedEvent::class, LoginFlowV2GrantedEvent::class, TokenInvalidatedEvent::class] as $event) {
			$context->registerEventListener($event, SecurityChangeListener::class);
		}
		foreach ([WasThisYouAnsweredEvent::class, DetectionCreatedEvent::class, PasswordUpdatedEvent::class] as $event) {
			$context->registerEventListener($event, SecureGuideListener::class);
		}
		$context->registerNotifierService(SecureAccountNotifier::class);
	}

	#[\Override]
	public function boot(IBootContext $context): void {
	}
}
