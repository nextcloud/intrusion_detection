<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\LoginMapper;
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
 * @template-implements IEventListener<UserLoggedInEvent>
 */
class LoginRecordListener implements IEventListener {
	public function __construct(
		private readonly Settings $settings,
		private readonly LoginMapper $logins,
		private readonly RemoteAddressResolver $addresses,
		private readonly ITimeFactory $timeFactory,
		private readonly LoggerInterface $logger,
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
			$this->logins->record($source->ipKey, $source->netKey, $event->getUser()->getUID(), $hour);
		} catch (\Throwable $e) {
			// A failure here must never break a login.
			$this->logger->error('Intrusion detection could not record a login', ['exception' => $e]);
		}
	}
}
