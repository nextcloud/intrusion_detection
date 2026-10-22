<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Db\LoginMapper;
use OCA\IntrusionDetection\Login\LoginGate;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\User\Events\UserLoggedInEvent;
use Psr\Log\LoggerInterface;

/**
 * Records which account logged in from which address, once per hour, for the
 * shared-address safety valve: an address many people log in from is not
 * blocked.
 *
 * Core reports a login for every WebDAV, CalDAV or app request with Basic
 * or Bearer credentials. With a memory cache only the first one per
 * address, account, credential and hour reaches the database (the
 * {@see LoginGate}, which the login history shares); without one, every one
 * costs a read of the row, and the insert only when it is missing.
 *
 * @template-implements IEventListener<UserLoggedInEvent>
 */
class LoginRecordListener implements IEventListener {
	public function __construct(
		private readonly AppSettings $settings,
		private readonly LoginMapper $logins,
		private readonly RemoteAddressResolver $addresses,
		private readonly ITimeFactory $timeFactory,
		private readonly LoggerInterface $logger,
		private readonly LoginGate $gate,
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
			$now = $this->timeFactory->getTime();
			$hour = intdiv($now, 3600);
			$uid = $event->getUser()->getUID();
			$first = $this->gate->isFirst($uid, $source->ipKey, $now);
			if ($first === false || ($first === null && $this->logins->exists($source->ipKey, $uid, $hour))) {
				return;
			}
			$this->logins->record($source->ipKey, $source->netKey, $uid, $hour);
		} catch (\Throwable $e) {
			// A failure here must never break a login.
			$this->logger->error('Intrusion detection could not record a login', ['exception' => $e]);
		}
	}
}
