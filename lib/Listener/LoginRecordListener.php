<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\LoginMapper;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\ICacheFactory;
use OCP\IMemcache;
use OCP\User\Events\UserLoggedInEvent;
use Psr\Log\LoggerInterface;

/**
 * Records which account logged in from which address, once per hour, for the
 * shared-address safety valve: an address many people log in from is not
 * blocked.
 *
 * Core reports a login for every WebDAV, CalDAV or app request with Basic
 * or Bearer credentials. With a memory cache only the first one per
 * address, account and hour reaches the database; without one, every one
 * costs a single insert that is skipped when the row exists.
 *
 * @template-implements IEventListener<UserLoggedInEvent>
 */
class LoginRecordListener implements IEventListener {
	private IMemcache|null|false $cache = false;

	public function __construct(
		private readonly Settings $settings,
		private readonly LoginMapper $logins,
		private readonly RemoteAddressResolver $addresses,
		private readonly ITimeFactory $timeFactory,
		private readonly LoggerInterface $logger,
		private readonly ICacheFactory $cacheFactory,
	) {
	}

	#[\Override]
	public function handle(Event $event): void {
		if (!$event instanceof UserLoggedInEvent || !$this->settings->isEnabled()) {
			return;
		}
		try {
			$source = $this->addresses->current();
			if ($source === null || $this->addresses->isBypassListed($source)) {
				return;
			}
			$hour = intdiv($this->timeFactory->getTime(), 3600);
			$uid = $event->getUser()->getUID();
			if (!$this->firstThisHour($source->ipKey, $uid, $hour)) {
				return;
			}
			$this->logins->record($source->ipKey, $source->netKey, $uid, $hour);
		} catch (\Throwable $e) {
			// A failure here must never break a login.
			$this->logger->error('Intrusion detection could not record a login', ['exception' => $e]);
		}
	}

	/**
	 * Whether this is the first login of the account from the address in the
	 * hour that this server knows of; always true without a memory cache.
	 */
	private function firstThisHour(string $ipKey, string $uid, int $hour): bool {
		if ($this->cache === false) {
			$cache = $this->cacheFactory->isAvailable()
				? $this->cacheFactory->createDistributed(Application::APP_ID . '-logins')
				: ($this->cacheFactory->isLocalCacheAvailable() ? $this->cacheFactory->createLocal(Application::APP_ID . '-logins') : null);
			// add() is atomic only on the memcache types.
			$this->cache = $cache instanceof IMemcache ? $cache : null;
		}
		return $this->cache === null || $this->cache->add(hash('sha256', $ipKey . "\0" . $uid) . ':' . $hour, 1, 3600);
	}
}
