<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\AppInfo;

use OCA\IntrusionDetection\Config\Lexicon;
use OCA\IntrusionDetection\Dashboard\IntrusionWidget;
use OCA\IntrusionDetection\Event\BanCreatedEvent;
use OCA\IntrusionDetection\Event\BanLiftedEvent;
use OCA\IntrusionDetection\Guard\AddressGuard;
use OCA\IntrusionDetection\Guard\PayloadGuard;
use OCA\IntrusionDetection\Guard\TrapUrlGuard;
use OCA\IntrusionDetection\Listener\BlocklistLoginListener;
use OCA\IntrusionDetection\Listener\FailedLoginListener;
use OCA\IntrusionDetection\Listener\FirewallExportListener;
use OCA\IntrusionDetection\Listener\LoginFlowGrantedListener;
use OCA\IntrusionDetection\Listener\LoginRecordListener;
use OCA\IntrusionDetection\Listener\PayloadLoginListener;
use OCA\IntrusionDetection\Listener\ResetRequestedListener;
use OCA\IntrusionDetection\Listener\ShareAccessFailedListener;
use OCA\IntrusionDetection\Middleware\PayloadMiddleware;
use OCA\IntrusionDetection\Notification\Notifier;
use OCA\IntrusionDetection\Notification\ShareOwnerNotifier;
use OCA\IntrusionDetection\SetupCheck\BlocklistSyncCheck;
use OCA\IntrusionDetection\TrustedNetwork\ITrustedNetworks;
use OCA\IntrusionDetection\TrustedNetwork\NullTrustedNetworks;
use OCP\AppFramework\App;
use OCP\AppFramework\Bootstrap\IBootContext;
use OCP\AppFramework\Bootstrap\IBootstrap;
use OCP\AppFramework\Bootstrap\IRegistrationContext;
use OCP\Authentication\Events\AnyLoginFailedEvent;
use OCP\Authentication\Events\LoginFlowV2GrantedEvent;
use OCP\Security\Events\PasswordResetRequestedEvent;
use OCP\Share\Events\ShareLinkAccessFailedEvent;
use OCP\User\Events\UserLoggedInEvent;

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
		$context->registerServiceAlias(ITrustedNetworks::class, NullTrustedNetworks::class);
		$context->registerEventListener(ShareLinkAccessFailedEvent::class, ShareAccessFailedListener::class);
		$context->registerEventListener(PasswordResetRequestedEvent::class, ResetRequestedListener::class);
		$context->registerEventListener(LoginFlowV2GrantedEvent::class, LoginFlowGrantedListener::class);
		$context->registerNotifierService(ShareOwnerNotifier::class);
	}

	#[\Override]
	public function boot(IBootContext $context): void {
	}
}
