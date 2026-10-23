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
use OCA\IntrusionDetection\SetupCheck\ProblemCheck;
use OCA\IntrusionDetection\SetupCheck\ReverseProxyCheck;
use OCA\IntrusionDetection\SetupCheck\SharedAddressCheck;
use OCA\IntrusionDetection\SetupCheck\StaleCredentialsCheck;
use OCA\IntrusionDetection\SetupCheck\TrapNameCollisionCheck;
use OCA\IntrusionDetection\SetupCheck\UsersWithoutConfirmationCheck;
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
use OCP\BeforeSabrePubliclyLoadedEvent;
use OCP\Group\Events\SubAdminAddedEvent;
use OCP\Group\Events\UserAddedEvent;
use OCP\Group\Events\UserRemovedEvent;
use OCP\Security\Events\PasswordResetRequestedEvent;
use OCP\SetupCheck\ISetupCheck;
use OCP\Share\Events\ShareLinkAccessFailedEvent;
use OCP\User\Events\PasswordUpdatedEvent;
use OCP\User\Events\UserChangedEvent;
use OCP\User\Events\UserCreatedEvent;
use OCP\User\Events\UserDeletedEvent;
use OCP\User\Events\UserLoggedInEvent;
use OCP\User\Events\UserLoggedInWithCookieEvent;

class Application extends App implements IBootstrap {
	public const APP_ID = 'intrusion_detection';
	/**
	 * Before core's and the other apps' login listeners, so that a new password
	 * required at login is asked for at once. The listener priorities live
	 * here: reading a listener's constant would load the listener on every
	 * request.
	 */
	public const LOGIN_PRIORITY = 10;
	/** After the other listeners of the events it watches */
	public const ADMIN_CHANGE_PRIORITY = -100;
	/**
	 * The setup checks shown in the status of the admin page
	 * ({@see SetupProblems}), registered with core's as well. They are listed
	 * here so that registering them loads no class.
	 *
	 * @var list<class-string<ProblemCheck>>
	 */
	public const SETUP_CHECKS = [
		ReverseProxyCheck::class,
		BruteForceProtectionCheck::class,
		MailCheck::class,
		MemoryCacheCheck::class,
		TrapNameCollisionCheck::class,
		SharedAddressCheck::class,
		LearningModeCheck::class,
		UsersWithoutConfirmationCheck::class,
		AdminContactCheck::class,
		AdminNetworksCheck::class,
		StaleCredentialsCheck::class,
	];
	/**
	 * Setup checks registered with core only: they are no ProblemCheck, so the
	 * status of the admin page leaves them out.
	 *
	 * @var list<class-string<ISetupCheck>>
	 */
	private const CORE_SETUP_CHECKS = [
		BlocklistSyncCheck::class,
		ApprovalCheck::class,
	];

	public function __construct(array $urlParams = []) {
		parent::__construct(self::APP_ID, $urlParams);
	}

	#[\Override]
	public function register(IRegistrationContext $context): void {
		$context->registerConfigLexicon(Lexicon::class);

		// Request guards run in registration order, on every web request.
		$context->registerRequestGuard(AddressGuard::class);
		$context->registerRequestGuard(TrapUrlGuard::class);
		$context->registerRequestGuard(PayloadGuard::class);
		$context->registerRequestGuard(CredentialUseGuard::class);

		$context->registerMiddleware(PayloadMiddleware::class, true);
		// Global, so that it covers every app's controllers; it runs after core's two-factor middleware.
		$context->registerMiddleware(SessionStateMiddleware::class, true);

		// Listeners of one event run by priority, and with the same priority in registration order.
		$context->registerEventListener(BanCreatedEvent::class, FirewallExportListener::class);
		$context->registerEventListener(BanLiftedEvent::class, FirewallExportListener::class);
		$context->registerEventListener(AnyLoginFailedEvent::class, FailedLoginListener::class);
		$context->registerEventListener(ShareLinkAccessFailedEvent::class, ShareAccessFailedListener::class);
		$context->registerEventListener(PasswordResetRequestedEvent::class, ResetRequestedListener::class);
		$context->registerEventListener(LoginFlowV2GrantedEvent::class, LoginFlowGrantedListener::class);
		$context->registerEventListener(PasswordUpdatedEvent::class, BreachResetListener::class);
		$context->registerEventListener(TwoFactorProviderChallengeFailed::class, SecondFactorFailedListener::class);
		$context->registerEventListener(AppPasswordCreatedEvent::class, AppPasswordCreatedListener::class);
		$context->registerEventListener(PasswordUpdatedEvent::class, PasswordUpdatedListener::class);
		$context->registerEventListener(UserDeletedEvent::class, UserDeletedListener::class);
		$context->registerEventListener(SettingChangedEvent::class, TrapNamesChangedListener::class);
		$context->registerEventListener(SabrePluginAddEvent::class, SabrePluginAddListener::class);
		$context->registerEventListener(BeforeSabrePubliclyLoadedEvent::class, SabrePluginAddListener::class);
		foreach ([UserAddedEvent::class, UserRemovedEvent::class, SubAdminAddedEvent::class, UserCreatedEvent::class, AppEnableEvent::class, AppDisableEvent::class, SettingChangedEvent::class] as $event) {
			$context->registerEventListener($event, AdminChangeListener::class, self::ADMIN_CHANGE_PRIORITY);
		}
		// One listener runs the app's login listeners, each only when the login concerns it.
		$context->registerEventListener(UserLoggedInEvent::class, LoginListener::class, self::LOGIN_PRIORITY);
		$context->registerEventListener(UserLoggedInWithCookieEvent::class, LoginListener::class, self::LOGIN_PRIORITY);
		$context->registerEventListener(TwoFactorProviderChallengePassed::class, StepUpChallengePassedListener::class);
		$context->registerEventListener(TwoFactorProviderForUserRegistered::class, UntrustedSecondFactorListener::class);
		$context->registerEventListener(TwoFactorProviderForUserUnregistered::class, UntrustedSecondFactorListener::class);
		$context->registerEventListener(TwoFactorProviderChallengePassed::class, LoginHistoryListener::class);
		$context->registerEventListener(WasThisYouAnsweredEvent::class, KnownDeviceListener::class);
		$context->registerEventListener(PasswordUpdatedEvent::class, KnownDeviceListener::class);
		foreach ([BeforePasswordResetEvent::class, PasswordResetEvent::class, UserChangedEvent::class, PasswordUpdatedEvent::class, TwoFactorProviderForUserRegistered::class, TwoFactorProviderForUserUnregistered::class, AppPasswordCreatedEvent::class, LoginFlowV2GrantedEvent::class, TokenInvalidatedEvent::class] as $event) {
			$context->registerEventListener($event, SecurityChangeListener::class);
		}
		foreach ([WasThisYouAnsweredEvent::class, DetectionCreatedEvent::class, PasswordUpdatedEvent::class] as $event) {
			$context->registerEventListener($event, SecureGuideListener::class);
		}

		$context->registerNotifierService(Notifier::class);
		$context->registerNotifierService(ShareOwnerNotifier::class);
		$context->registerNotifierService(SecureAccountNotifier::class);

		foreach ([...self::CORE_SETUP_CHECKS, ...self::SETUP_CHECKS] as $setupCheck) {
			$context->registerSetupCheck($setupCheck);
		}

		$context->registerDashboardWidget(IntrusionWidget::class);

		$context->registerServiceAlias(ITrustedNetworks::class, TrustedNetworks::class);
		$context->registerServiceAlias(IKnownDevices::class, KnownDevices::class);
		$context->registerServiceAlias(IAcceptedLogins::class, LoginHistory::class);
	}

	#[\Override]
	public function boot(IBootContext $context): void {
	}
}
