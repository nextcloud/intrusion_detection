<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\IntrusionDetection\Check\Checks\LoginFlowMismatch\LoginFlowMismatch;
use OCA\IntrusionDetection\Check\Checks\LoginFlowMismatch\LoginFlowMismatchDetector;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCP\Authentication\Events\LoginFlowV2GrantedEvent;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\IRequest;
use Psr\Log\LoggerInterface;

/**
 * A login flow v2 request was granted: judge where it was started and
 * where it was approved (the current request). Returns at once while the
 * check is off; every failure is logged and ignored, so granting a device
 * never breaks.
 *
 * @template-implements IEventListener<LoginFlowV2GrantedEvent>
 */
class LoginFlowGrantedListener implements IEventListener {
	public function __construct(
		private readonly CheckSettings $settings,
		private readonly RemoteAddressResolver $addresses,
		private readonly LoginFlowMismatchDetector $detector,
		private readonly IRequest $request,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function handle(Event $event): void {
		if (!$event instanceof LoginFlowV2GrantedEvent) {
			return;
		}
		try {
			if (!$this->settings->modeState(LoginFlowMismatch::ID)->runs()) {
				return;
			}
			$granter = $this->addresses->current();
			if ($granter === null) {
				return;
			}
			$this->detector->granted($event->getToken(), $event->getInitiatorIp(), $event->getStartedAt(), $granter, $this->request->getHeader('User-Agent'));
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not check a granted login flow', ['exception' => $e]);
		}
	}
}
