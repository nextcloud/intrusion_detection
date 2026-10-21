<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Listener;

use OC\Authentication\TwoFactorAuth\Manager as TwoFactorManager;
use OC\Core\Events\BeforePasswordResetEvent;
use OC\Core\Events\PasswordResetEvent;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\SecurityChangeMapper;
use OCA\IntrusionDetection\Response\Tokens;
use OCA\IntrusionDetection\Takeover\ResetTracker;
use OCA\IntrusionDetection\Takeover\SecurityChangeLog;
use OCA\IntrusionDetection\Takeover\SecurityChangeType;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Authentication\Events\AppPasswordCreatedEvent;
use OCP\Authentication\Events\LoginFlowV2GrantedEvent;
use OCP\Authentication\Events\TokenInvalidatedEvent;
use OCP\Authentication\Token\IToken;
use OCP\Authentication\TwoFactorAuth\IRegistry;
use OCP\Authentication\TwoFactorAuth\TwoFactorProviderForUserRegistered;
use OCP\Authentication\TwoFactorAuth\TwoFactorProviderForUserUnregistered;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\User\Events\PasswordUpdatedEvent;
use OCP\User\Events\UserChangedEvent;
use Psr\Log\LoggerInterface;

/**
 * Writes the security change log (concept section 10.14) from core's events:
 *
 * - the email address changed (`UserChangedEvent`, feature eMailAddress);
 * - the password changed (`PasswordUpdatedEvent`); a reset through the
 *   "forgot password" email is logged as such and never counts, since it
 *   proves access to the email address;
 * - a second factor registered or unregistered; removing the last one is
 *   logged as two-factor authentication turned off. Core recording the
 *   state of a provider it had none for is no change. Core's
 *   `TwoFactorProviderForUserDisabled` is not used: despite its name, core
 *   dispatches it for every failed challenge;
 * - an app password created, or a device connected through the login flow
 *   (which also creates an app password: the same change, logged once);
 * - an app password revoked (`TokenInvalidatedEvent` for permanent tokens).
 *
 * Runs while the app is enabled, whatever the takeover check's mode: the
 * log also feeds the personal page and incident reports. Fails open.
 *
 * @template-implements IEventListener<Event>
 */
class SecurityChangeListener implements IEventListener {
	/** A device connected within this time after its app password was created is the same change */
	public const SAME_CHANGE_WINDOW = 300;
	private const BACKUP_CODES = 'backup_codes';

	public function __construct(
		private readonly Settings $settings,
		private readonly SecurityChangeLog $log,
		private readonly SecurityChangeMapper $changes,
		private readonly ResetTracker $resets,
		private readonly IRegistry $twoFactorRegistry,
		private readonly ITimeFactory $timeFactory,
		private readonly LoggerInterface $logger,
	) {
	}

	#[\Override]
	public function handle(Event $event): void {
		try {
			if ($event instanceof BeforePasswordResetEvent) {
				$this->resets->start($event->getUser()->getUID());
				return;
			}
			if ($event instanceof PasswordResetEvent) {
				$this->resets->end($event->getUser()->getUID());
				return;
			}
			if (!$this->settings->isEnabled()) {
				return;
			}
			match (true) {
				$event instanceof UserChangedEvent => $this->userChanged($event),
				$event instanceof PasswordUpdatedEvent => $this->log->record($event->getUser()->getUID(), SecurityChangeType::PasswordChanged),
				$event instanceof TwoFactorProviderForUserRegistered => self::isStateBackfill() ? null : $this->log->record($event->getUser()->getUID(), SecurityChangeType::SecondFactorAdded, detail: $event->getProvider()->getId()),
				$event instanceof TwoFactorProviderForUserUnregistered => self::isStateBackfill() ? null : $this->secondFactorRemoved($event),
				$event instanceof AppPasswordCreatedEvent => $this->appPassword($event->getToken(), SecurityChangeType::AppPasswordCreated),
				$event instanceof LoginFlowV2GrantedEvent => $this->deviceConnected($event->getToken()),
				$event instanceof TokenInvalidatedEvent => $this->tokenInvalidated($event->getToken()),
				default => null,
			};
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection could not record a security change', ['exception' => $e]);
		}
	}

	/**
	 * Whether core is only recording the unknown state of a provider (at a
	 * login, for providers it has no state for yet), not changing it: core
	 * dispatches the same registered and unregistered events then. Without
	 * this, the first login after a provider app was enabled would look like
	 * every user turning their second factor off.
	 */
	private static function isStateBackfill(): bool {
		foreach (debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 24) as $frame) {
			if (($frame['function'] ?? '') === 'fixMissingProviderStates' && ($frame['class'] ?? '') === TwoFactorManager::class) {
				return true;
			}
		}
		return false;
	}

	private function userChanged(UserChangedEvent $event): void {
		if ($event->getFeature() !== 'eMailAddress') {
			return;
		}
		$old = $event->getOldValue();
		$new = $event->getValue();
		$old = is_string($old) && $old !== '' ? $old : null;
		$new = is_string($new) && $new !== '' ? $new : null;
		if ($old === $new || ($old !== null && $new !== null && strcasecmp($old, $new) === 0)) {
			return;
		}
		$this->log->record($event->getUser()->getUID(), SecurityChangeType::EmailChanged, $old, $new);
	}

	private function secondFactorRemoved(TwoFactorProviderForUserUnregistered $event): void {
		$user = $event->getUser();
		$remaining = false;
		foreach ($this->twoFactorRegistry->getProviderStates($user) as $providerId => $enabled) {
			if ($enabled && $providerId !== self::BACKUP_CODES && $providerId !== $event->getProvider()->getId()) {
				$remaining = true;
				break;
			}
		}
		$type = $remaining || $event->getProvider()->getId() === self::BACKUP_CODES ? SecurityChangeType::SecondFactorRemoved : SecurityChangeType::SecondFactorDisabled;
		$this->log->record($user->getUID(), $type, detail: $event->getProvider()->getId());
	}

	private function appPassword(IToken $token, SecurityChangeType $type): void {
		$this->log->record($token->getUID(), $type, refId: $token->getId(), detail: Tokens::name($token));
	}

	private function deviceConnected(IToken $token): void {
		$since = $this->timeFactory->getTime() - self::SAME_CHANGE_WINDOW;
		[$via] = $this->log->actor($token->getUID());
		if ($this->changes->retype($token->getUID(), $token->getId(), SecurityChangeType::AppPasswordCreated->value, SecurityChangeType::DeviceConnected->value, $via, $since)) {
			return;
		}
		$this->appPassword($token, SecurityChangeType::DeviceConnected);
	}

	private function tokenInvalidated(IToken $token): void {
		// Browser sessions end at every logout; only app passwords are security changes.
		if ($token->getType() !== IToken::PERMANENT_TOKEN) {
			return;
		}
		$this->appPassword($token, SecurityChangeType::AppPasswordRevoked);
	}
}
