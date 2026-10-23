<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Confirm;

use OC\Authentication\TwoFactorAuth\ProviderLoader;
use OCP\Authentication\TwoFactorAuth\IProvidesPersonalSettings;
use OCP\Authentication\TwoFactorAuth\IRegistry;
use OCP\IUser;
use Psr\Log\LoggerInterface;

/**
 * The second factors of an account, as the app counts them: backup codes
 * alone are none, as in core.
 *
 * The providers set up for an account come from core's public registry.
 * Which providers the server offers an account comes from core's
 * `ProviderLoader`, which has no public counterpart.
 */
class SecondFactors {
	public const BACKUP_CODES = 'backup_codes';

	public function __construct(
		private readonly IRegistry $registry,
		private readonly ProviderLoader $providers,
		private readonly UntrustedSecondFactors $untrusted,
		private readonly LoggerInterface $logger,
	) {
	}

	/**
	 * Whether the account has a second factor set up.
	 *
	 * @param ?string $except a provider not to count, e.g. one being removed
	 */
	public function has(IUser $user, ?string $except = null): bool {
		return $this->setUp($user, $except) !== [];
	}

	/**
	 * Whether the account has a second factor that confirms a login: one
	 * not set up from a session that proved only the password
	 * ({@see UntrustedSecondFactors}).
	 */
	public function trusted(IUser $user): bool {
		$untrusted = $this->untrusted->marks($user->getUID());
		foreach ($this->setUp($user) as $providerId) {
			if (!isset($untrusted[$providerId])) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Whether passing the challenge of this provider confirms a login.
	 */
	public function confirms(IUser $user, string $providerId): bool {
		return $this->untrusted->isTrusted($user->getUID(), $providerId);
	}

	/**
	 * Whether the server offers the account a second factor; with
	 * `$settable` only one the user can set up in the personal settings.
	 */
	public function available(IUser $user, bool $settable = false): bool {
		try {
			foreach ($this->providers->getProviders($user) as $provider) {
				if ($provider->getId() !== self::BACKUP_CODES && (!$settable || $provider instanceof IProvidesPersonalSettings)) {
					return true;
				}
			}
		} catch (\Throwable $e) {
			$this->logger->warning('Intrusion detection could not list the second factors available to {uid}', ['uid' => $user->getUID(), 'exception' => $e]);
		}
		return false;
	}

	/**
	 * @return list<string> the ids of the providers set up for the account
	 */
	private function setUp(IUser $user, ?string $except = null): array {
		$ids = [];
		try {
			foreach ($this->registry->getProviderStates($user) as $providerId => $enabled) {
				if ($enabled && $providerId !== self::BACKUP_CODES && $providerId !== $except) {
					$ids[] = (string)$providerId;
				}
			}
		} catch (\Throwable $e) {
			$this->logger->warning('Intrusion detection could not read the second factors of {uid}', ['uid' => $user->getUID(), 'exception' => $e]);
		}
		return $ids;
	}
}
