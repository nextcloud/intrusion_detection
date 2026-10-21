<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OCA\IntrusionDetection\Check\Checks\AccountUnderAttack;
use OCA\IntrusionDetection\Check\Checks\AccountUnderAttackDetector;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffing;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffingDetector;
use OCA\IntrusionDetection\Check\Checks\DecoyCredentialDetector;
use OCA\IntrusionDetection\Check\Checks\PasswordSpraying;
use OCA\IntrusionDetection\Check\Checks\PasswordSprayingDetector;
use OCA\IntrusionDetection\Check\Checks\ReservedNameDetector;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Detection\AttemptRecorder;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCP\Authentication\Events\AnyLoginFailedEvent;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\IRequest;
use OCP\IUserManager;
use Psr\Log\LoggerInterface;

/**
 * Every failed password check (login form, Basic auth on WebDAV and OCS,
 * login flow), in the order of concept section 12.1:
 *
 * 1. a source on the brute-force allowlist is ignored;
 * 2. a decoy credential, and then a reserved login name, is a detection on
 *    its own, and nothing else runs;
 * 3. the attempt is recorded, if any check uses it (fingerprints only; old
 *    attempts are cleaned up now and then by the recorder);
 * 4. the detectors of the checks that use failed logins run: password
 *    spraying (a password that is already being sprayed blocks its address
 *    at once), credential stuffing, and one account attacked from many places.
 *
 * Nothing here may break a login failure: every step fails open and logs.
 * The password is only passed on to be fingerprinted, never stored or logged.
 *
 * @template-implements IEventListener<AnyLoginFailedEvent>
 */
class FailedLoginListener implements IEventListener {
	/** Generated app passwords: five groups of five characters, or 72 letters and digits */
	public const APP_PASSWORD_PATTERN = '/^(?:[A-Za-z0-9]{5}(?:-[A-Za-z0-9]{5}){4}|[A-Za-z0-9]{72})$/';
	/** The checks that read the recorded failed logins */
	public const ATTEMPT_CHECKS = [PasswordSpraying::ID, CredentialStuffing::ID, AccountUnderAttack::ID];
	/** Longer login names are not looked up as accounts */
	public const MAX_LOGIN_NAME = 255;

	public function __construct(
		private readonly Settings $settings,
		private readonly RemoteAddressResolver $addresses,
		private readonly AttemptRecorder $recorder,
		private readonly DecoyCredentialDetector $decoys,
		private readonly ReservedNameDetector $reservedNames,
		private readonly CredentialStuffingDetector $stuffing,
		private readonly PasswordSprayingDetector $spraying,
		private readonly AccountUnderAttackDetector $accountUnderAttack,
		private readonly IUserManager $userManager,
		private readonly IRequest $request,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function handle(Event $event): void {
		if (!$event instanceof AnyLoginFailedEvent) {
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
			$loginName = $event->getLoginName();
			$password = $event->getPassword();
			$userAgent = $this->request->getHeader('User-Agent');

			if ($this->step('decoy_credential', fn (): bool => $this->decoys->detect($source, $loginName, $password, $userAgent)) === true) {
				return;
			}
			if ($this->step('reserved_name', fn (): bool => $this->reservedNames->detect($source, $loginName, $userAgent)) === true) {
				return;
			}

			if (!$this->anyDetectorRuns()) {
				return;
			}
			$attempt = $this->recorder->record(
				self::kindOf($password),
				$source,
				$loginName,
				$this->resolveUid($loginName),
				null,
				$password,
			);

			$this->step('password_spraying', fn () => $this->spraying->detect($attempt, $userAgent, $password));
			$this->step('credential_stuffing', fn () => $this->stuffing->detect($attempt, $userAgent));
			$this->step('account_under_attack', fn () => $this->accountUnderAttack->detect($attempt, $userAgent));
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not process a failed login', ['exception' => $e]);
		}
	}

	/**
	 * Attempts are only recorded while a check uses them.
	 */
	private function anyDetectorRuns(): bool {
		foreach (self::ATTEMPT_CHECKS as $checkId) {
			if ($this->settings->modeState($checkId)->runs()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * A password with the exact shape of a generated app password is taken
	 * for one: core does not say whether it tried the password as a token.
	 */
	public static function kindOf(#[\SensitiveParameter] ?string $password): AttemptKind {
		return $password !== null && preg_match(self::APP_PASSWORD_PATTERN, $password) === 1
			? AttemptKind::AppPassword
			: AttemptKind::PasswordLogin;
	}

	/**
	 * The account a login name belongs to, the way core resolves it: the
	 * login name mapping of user backends, the uid itself, or an email address
	 * that exactly one account has. Nothing is returned to the client, so
	 * this reveals nothing.
	 */
	private function resolveUid(string $loginName): ?string {
		$name = trim($loginName);
		if ($name === '' || strlen($name) > self::MAX_LOGIN_NAME) {
			return null;
		}
		$user = $this->userManager->get($this->userManager->getUserNameFromLoginName($name));
		if ($user !== null) {
			return $user->getUID();
		}
		if (filter_var($name, FILTER_VALIDATE_EMAIL) !== false) {
			$users = $this->userManager->getByEmail($name);
			if (count($users) === 1) {
				return $users[0]->getUID();
			}
		}
		return null;
	}

	/**
	 * Run one step; a failing step is logged and the next one still runs.
	 *
	 * @template T
	 * @param \Closure(): T $step
	 * @return T|null
	 */
	private function step(string $name, \Closure $step): mixed {
		try {
			return $step();
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection step {step} failed on a failed login', ['step' => $name, 'exception' => $e]);
			return null;
		}
	}
}
