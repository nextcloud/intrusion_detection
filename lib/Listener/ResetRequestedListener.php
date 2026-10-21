<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\IntrusionDetection\Check\Checks\ResetProbing;
use OCA\IntrusionDetection\Check\Checks\ResetProbingDetector;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Detection\AttemptRecorder;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Response\ResetMailSuppressor;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\IRequest;
use OCP\IUserManager;
use OCP\Security\Events\PasswordResetRequestedEvent;
use Psr\Log\LoggerInterface;

/**
 * Every password reset request (concept section 12.3):
 *
 * 1. records an attempt of kind 6 with a fingerprint of the input, and the
 *    account it belongs to, resolved the way core resolves it for the email;
 * 2. runs the reset abuse detector;
 * 3. prevents the email while the account's reset emails are held back.
 *
 * Core answers the request the same way whatever happens here, so nothing
 * this listener does is visible to the requester. Returns at once while the
 * check is off and for sources on the brute-force allowlist; every failure
 * is logged and ignored.
 *
 * @template-implements IEventListener<PasswordResetRequestedEvent>
 */
class ResetRequestedListener implements IEventListener {
	/** Longer inputs are not looked up as accounts; core refuses them before this event */
	public const MAX_INPUT = 255;

	public function __construct(
		private readonly Settings $settings,
		private readonly RemoteAddressResolver $addresses,
		private readonly AttemptRecorder $recorder,
		private readonly ResetProbingDetector $detector,
		private readonly ResetMailSuppressor $suppressor,
		private readonly IUserManager $userManager,
		private readonly IRequest $request,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function handle(Event $event): void {
		if (!$event instanceof PasswordResetRequestedEvent) {
			return;
		}
		try {
			$state = $this->settings->modeState(ResetProbing::ID);
			if (!$state->runs()) {
				return;
			}
			$source = $this->addresses->current();
			if ($source === null || $this->addresses->isBypassListed($source)) {
				return;
			}
			$input = $event->getInput();
			$uid = $this->resolveUid($input);
			$attempt = $this->recorder->record(AttemptKind::PasswordReset, $source, $input, $uid);
			try {
				$this->detector->detect($attempt, $this->request->getHeader('User-Agent'));
			} catch (\Throwable $e) {
				$this->logger->error('Intrusion detection could not check a password reset request', ['exception' => $e]);
			}
			if ($uid !== null && $state->acts()) {
				$this->suppressor->apply($event, $uid);
			}
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not process a password reset request', ['exception' => $e]);
		}
	}

	/**
	 * The account core would send the email to, like
	 * `LostController::findUserByIdOrMail()`: an enabled account with this
	 * uid, or the only enabled account with this email address. Nothing is
	 * returned to the requester, so this reveals nothing.
	 */
	private function resolveUid(#[\SensitiveParameter] string $input): ?string {
		$input = trim($input);
		if ($input === '' || strlen($input) > self::MAX_INPUT) {
			return null;
		}
		$user = $this->userManager->get($input);
		if ($user !== null) {
			return $user->isEnabled() ? $user->getUID() : null;
		}
		if (!str_contains($input, '@')) {
			return null;
		}
		$enabled = array_values(array_filter($this->userManager->getByEmail($input), static fn ($u): bool => $u->isEnabled()));
		return count($enabled) === 1 ? $enabled[0]->getUID() : null;
	}
}
