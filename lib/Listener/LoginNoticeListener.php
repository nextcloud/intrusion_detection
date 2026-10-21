<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Lockdown\LockdownState;
use OCP\AppFramework\Http\Events\BeforeLoginTemplateRenderedEvent;
use OCP\AppFramework\Services\IInitialState;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\IL10N;
use OCP\Util;
use Psr\Log\LoggerInterface;

/**
 * During lockdown, a short notice on core's login page (concept section
 * 11.14): "Extra security checks are active. You may be asked to confirm
 * your login." Administrators can change it (`lockdown_login_notice`).
 *
 * Core's login page is built by a script from its initial state, and core
 * offers no hook to add a message to it. So the login page gets the text
 * as initial state of this app and a tiny script that shows it above the
 * login box: nothing at all is added outside a lockdown, and the login
 * page itself is unchanged.
 *
 * @template-implements IEventListener<BeforeLoginTemplateRenderedEvent>
 */
class LoginNoticeListener implements IEventListener {
	public const SCRIPT = 'login-notice';
	public const STATE = 'login-notice';

	public function __construct(
		private readonly LockdownState $lockdown,
		private readonly Settings $settings,
		private readonly IInitialState $initialState,
		private readonly IL10N $l,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function handle(Event $event): void {
		if (!$event instanceof BeforeLoginTemplateRenderedEvent) {
			return;
		}
		try {
			if (!$this->lockdown->isActive()) {
				return;
			}
			$notice = trim((string)$this->settings->global(GlobalSettings::LOCKDOWN_LOGIN_NOTICE));
			$this->initialState->provideInitialState(self::STATE, $notice !== '' ? $notice : self::defaultNotice($this->l));
			Util::addScript(Application::APP_ID, self::SCRIPT);
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not add the lockdown notice to the login page', ['exception' => $e]);
		}
	}

	public static function defaultNotice(IL10N $l): string {
		return $l->t('Extra security checks are active. You may be asked to confirm your login.');
	}
}
