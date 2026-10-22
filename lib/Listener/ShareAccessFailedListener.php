<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\IntrusionDetection\Check\Checks\ShareBruteforce\ShareBruteforce;
use OCA\IntrusionDetection\Check\Checks\ShareBruteforce\ShareBruteforceDetector;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Detection\AttemptRecorder;
use OCA\IntrusionDetection\Net\FetchMetadata;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\IRequest;
use OCP\IUserSession;
use OCP\Share\Events\ShareLinkAccessFailedEvent;
use Psr\Log\LoggerInterface;

/**
 * Every failed access to a public share link (the share page and public
 * WebDAV): records an attempt of kind 4 (unknown token: only the token's
 * fingerprint) or kind 5 (wrong password: the share's id), then runs the
 * share link attack detector.
 *
 * Returns at once while the check is off and for sources on the
 * brute-force allowlist. Unknown tokens from logged-in users are recorded
 * with their account and reported, but never block their address: someone
 * with a valid session who follows old links is rarely an attacker, and is
 * known to the server anyway. Nothing here may break a share access: every
 * failure is logged and ignored. The token is never logged or stored.
 *
 * @template-implements IEventListener<ShareLinkAccessFailedEvent>
 */
class ShareAccessFailedListener implements IEventListener {
	public function __construct(
		private readonly CheckSettings $settings,
		private readonly RemoteAddressResolver $addresses,
		private readonly AttemptRecorder $recorder,
		private readonly ShareBruteforceDetector $detector,
		private readonly IRequest $request,
		private readonly IUserSession $userSession,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function handle(Event $event): void {
		if (!$event instanceof ShareLinkAccessFailedEvent) {
			return;
		}
		try {
			if (!$this->settings->modeState(ShareBruteforce::ID)->runs()) {
				return;
			}
			$source = $this->addresses->current();
			if ($source === null || $this->addresses->isBypassListed($source)) {
				return;
			}
			$userAgent = $this->request->getHeader('User-Agent');

			if ($event->getReason() === ShareLinkAccessFailedEvent::REASON_NOT_FOUND) {
				$attempt = $this->recorder->recordUnknownShareToken($source, $event->getToken(), FetchMetadata::isLure($this->request), $this->userSession->getUser()?->getUID());
				$this->detector->unknownToken($attempt, $userAgent);
				return;
			}

			$share = $event->getShare();
			$shareId = $share?->getId();
			// Every share provider in core numbers its shares; anything else cannot be counted per share.
			if ($share === null || $shareId === null || !ctype_digit($shareId) || strlen($shareId) > 18) {
				return;
			}
			$attempt = $this->recorder->record(AttemptKind::WrongSharePassword, $source, shareId: (int)$shareId);
			$this->detector->wrongPassword($attempt, $share, $userAgent);
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not process a failed share access', ['exception' => $e]);
		}
	}
}
