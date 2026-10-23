<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\IntrusionDetection\Check\Checks\ResetProbing\ResetProbing;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Db\KeyMatch;
use OCA\IntrusionDetection\Detection\AttemptRecorder;
use OCA\IntrusionDetection\KnownDevice\KnownDevices;
use OCA\IntrusionDetection\Login\EmailAccounts;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\IAcceptedLogins;
use OCA\IntrusionDetection\Response\ResetMailSuppressor;
use OCA\IntrusionDetection\Signal\ResetRequested;
use OCA\IntrusionDetection\Signal\SignalDispatcher;
use OCP\AppFramework\Utility\ITimeFactory;
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
 * 2. hands it to the reset abuse check ({@see ResetRequested});
 * 3. prevents the email while the account's reset emails are held back,
 *    unless the request comes from the account holder: from a remembered
 *    device of the account, or from an address the account confirmed a
 *    login from (a second factor, an email code, admin approval or a
 *    remembered device) within {@see ResetProbing::HOLDER_LOGIN_AGE}.
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
		private readonly SignalDispatcher $dispatcher,
		private readonly RemoteAddressResolver $addresses,
		private readonly AttemptRecorder $recorder,
		private readonly ResetMailSuppressor $suppressor,
		private readonly IUserManager $userManager,
		private readonly IRequest $request,
		private readonly LoggerInterface $logger,
		private readonly EmailAccounts $emailAccounts,
		private readonly KnownDevices $knownDevices,
		private readonly IAcceptedLogins $logins,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	#[\Override]
	public function handle(Event $event): void {
		if (!$event instanceof PasswordResetRequestedEvent) {
			return;
		}
		try {
			if (!$this->dispatcher->runs(ResetRequested::class)) {
				return;
			}
			$source = $this->addresses->current();
			if ($source === null || $this->addresses->isBypassListed($source)) {
				return;
			}
			$input = $event->getInput();
			$uid = $this->resolveUid($input);
			$attempt = $this->recorder->record(AttemptKind::PasswordReset, $source, $input, $uid);
			$this->dispatcher->dispatch(new ResetRequested($attempt, $this->request->getHeader('User-Agent')));
			if ($uid !== null && $this->dispatcher->acts(ResetRequested::class)
				&& $this->suppressor->isSuppressed($uid) && !$this->fromAccountHolder($uid, $source)) {
				$event->preventEmail();
			}
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not process a password reset request', ['exception' => $e]);
		}
	}

	private function fromAccountHolder(string $uid, SourceKey $source): bool {
		if ($this->knownDevices->recognise($uid) !== null) {
			return true;
		}
		[$column, $keys] = KeyMatch::address($source);
		return $this->logins->hasConfirmedLogin($uid, $column, $keys, $this->timeFactory->getTime() - ResetProbing::HOLDER_LOGIN_AGE);
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
		return $this->emailAccounts->only($input, true);
	}
}
