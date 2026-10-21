<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Sensitive;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Confirm\NoMethodOutcome;
use OCA\IntrusionDetection\Http\LocalRedirect;
use OCA\IntrusionDetection\Lockdown\LockdownEffect;
use OCA\IntrusionDetection\Lockdown\LockdownState;
use OCA\IntrusionDetection\Notification\AdminNotices;
use OCA\IntrusionDetection\SessionState\SessionBlock;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCP\IRequest;
use OCP\IURLGenerator;
use OCP\IUserManager;
use OCP\L10N\IFactory;
use Psr\Container\ContainerInterface;

/**
 * Decides a request to a sensitive route (concept sections 11.13 and 11.14),
 * once {@see SensitiveRoutes} found its route name:
 *
 * 1. During lockdown, new devices are refused outright.
 * 2. A group the administrator switched off is not protected.
 * 3. A session that is not risky, or confirmed within
 *    `sensitive_confirm_ttl`, may go ahead ({@see SensitiveSession}).
 * 4. A share is only sensitive when it reaches outside the server and is
 *    large ({@see ShareSize}).
 * 5. An account that cannot confirm anything goes ahead with a notice to
 *    the administrators, when `sensitive_no_method` allows it.
 * 6. Otherwise: 403 with the URL of the confirm page.
 */
class SensitiveActions {
	public const ERROR_DEVICES_LOCKED = 'devices_locked';
	public const LOCKDOWN_HEADER = 'X-Nextcloud-Lockdown';

	public function __construct(
		private readonly Settings $settings,
		private readonly SensitiveSession $session,
		private readonly LockdownState $lockdown,
		private readonly IRequest $request,
		private readonly IURLGenerator $urlGenerator,
		private readonly IFactory $l10nFactory,
		private readonly IUserManager $userManager,
		private readonly AuditLogger $audit,
		private readonly ContainerInterface $container,
	) {
	}

	public function check(SessionState $state, string $route, string $uid, string $requestUri): ?SessionBlock {
		$param = fn (string $name): mixed => $this->request->getParam($name);
		$group = SensitiveRoutes::group($route, $param, $this->settings->getBool(GlobalSettings::SENSITIVE_INCLUDE_DISPLAY_NAME));
		if ($group === null) {
			return null;
		}
		if ($group === SensitiveRoutes::GROUP_DEVICES && $this->lockdown->applies(LockdownEffect::Devices)) {
			$this->audit->log('new device of %s refused: lockdown', ['uid' => $uid]);
			$message = $this->l10nFactory->get(Application::APP_ID)->t('New devices cannot be connected right now. Please try again later.');
			return SessionBlock::refused(self::ERROR_DEVICES_LOCKED, self::LOCKDOWN_HEADER, $message, $this->urlGenerator->linkToRoute(Application::APP_ID . '.Confirm.unavailable'));
		}
		$groups = $this->settings->global(GlobalSettings::SENSITIVE_GROUPS);
		if (!is_array($groups) || !in_array($group, $groups, true)) {
			return null;
		}
		$reason = $this->session->riskReason($state, $uid);
		if ($reason === null || $this->session->isConfirmed($state, $uid)) {
			return null;
		}
		if (SensitiveRoutes::needsShareCheck($route)
			&& (!SensitiveRoutes::isOutsideShare($param) || !$this->container->get(ShareSize::class)->isLarge($uid, (string)$param('path')))) {
			return null;
		}
		if ($this->allowedWithoutMethod($uid, $group)) {
			return null;
		}
		$l = $this->l10nFactory->get(Application::APP_ID);
		$back = $this->isPageRequest() ? $requestUri : $this->referrer();
		return SessionBlock::confirmationRequired(
			$this->urlGenerator->linkToRoute(Application::APP_ID . '.Confirm.show', $back === null ? [] : ['redirect_url' => $back]),
			$l->t('To do this, confirm it\'s you.'),
			[
				'title' => $l->t('Confirm it\'s you'),
				'text' => $l->t('To do this, confirm it\'s you. You come back to this page afterwards; then do it again.'),
				'confirm' => $l->t('Confirm'),
				'cancel' => $l->t('Cancel'),
			],
		);
	}

	/**
	 * With `sensitive_no_method` on allow_notify, an account that has no way
	 * to confirm goes ahead, and the administrators are told.
	 */
	private function allowedWithoutMethod(string $uid, string $group): bool {
		if ($this->settings->global(GlobalSettings::SENSITIVE_NO_METHOD) !== NoMethodOutcome::AllowNotify->value) {
			return false;
		}
		$user = $this->userManager->get($uid);
		if ($user === null || $this->container->get(SensitiveConfirmations::class)->methodsFor($user) !== []) {
			return false;
		}
		$this->audit->log('sensitive action of %s (%s) allowed without confirmation: the account cannot confirm', ['uid' => $uid, 'group' => $group]);
		$this->container->get(AdminNotices::class)->sensitiveUnconfirmed($uid, $group);
		return true;
	}

	/**
	 * A browser opening a page, which it can open again after confirming.
	 */
	private function isPageRequest(): bool {
		return $this->request->getMethod() === 'GET'
			&& stripos($this->request->getHeader('Accept'), 'html') !== false
			&& $this->request->getHeader('X-Requested-With') === '';
	}

	/**
	 * The page a script's request came from, when it is a page of this
	 * server, so that the confirm page can return to it.
	 */
	private function referrer(): ?string {
		$referrer = $this->request->getHeader('Referer');
		$parts = parse_url($referrer);
		if ($referrer === '' || !is_array($parts) || !isset($parts['path'])
			|| (isset($parts['host']) && strcasecmp($parts['host'], $this->request->getServerHost()) !== 0 && strcasecmp($parts['host'] . (isset($parts['port']) ? ':' . $parts['port'] : ''), $this->request->getServerHost()) !== 0)) {
			return null;
		}
		$path = $parts['path'] . (isset($parts['query']) ? '?' . $parts['query'] : '');
		return LocalRedirect::isSafe($path, ActionConfirmationFlow::EXCLUDED) ? $path : null;
	}
}
