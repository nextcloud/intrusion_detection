<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Signal\SecondFactorFailure;
use OCA\IntrusionDetection\Signal\SignalDispatcher;
use OCP\Authentication\TwoFactorAuth\TwoFactorProviderChallengeFailed;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\IRequest;
use Psr\Log\LoggerInterface;

/**
 * A second-factor challenge failed after a correct password (concept
 * section 10.4). Sources on the brute-force allowlist are ignored. Nothing
 * here may break the challenge page: every failure is logged, not thrown.
 *
 * @template-implements IEventListener<TwoFactorProviderChallengeFailed>
 */
class SecondFactorFailedListener implements IEventListener {
	public function __construct(
		private readonly AppSettings $settings,
		private readonly RemoteAddressResolver $addresses,
		private readonly SignalDispatcher $dispatcher,
		private readonly IRequest $request,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function handle(Event $event): void {
		if (!$event instanceof TwoFactorProviderChallengeFailed) {
			return;
		}
		try {
			if (!$this->settings->isEnabled()) {
				return;
			}
			$source = $this->addresses->current();
			if ($source === null || $this->addresses->isBypassListed($source)) {
				return;
			}
			$provider = $event->getProvider();
			$this->dispatcher->dispatch(new SecondFactorFailure($event->getUser(), $provider->getId(), $provider->getDisplayName(), $source, $this->request->getHeader('User-Agent')));
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not process a failed second factor', ['exception' => $e]);
		}
	}
}
