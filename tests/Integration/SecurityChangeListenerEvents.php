<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\Core\Events\BeforePasswordResetEvent;
use OC\Core\Events\PasswordResetEvent;
use OCP\Authentication\Events\AppPasswordCreatedEvent;
use OCP\Authentication\Events\LoginFlowV2GrantedEvent;
use OCP\Authentication\Events\TokenInvalidatedEvent;
use OCP\Authentication\TwoFactorAuth\TwoFactorProviderForUserRegistered;
use OCP\Authentication\TwoFactorAuth\TwoFactorProviderForUserUnregistered;
use OCP\User\Events\PasswordUpdatedEvent;
use OCP\User\Events\UserChangedEvent;

/**
 * The events the security change listener is registered for.
 */
final class SecurityChangeListenerEvents {
	public const ALL = [
		BeforePasswordResetEvent::class,
		PasswordResetEvent::class,
		UserChangedEvent::class,
		PasswordUpdatedEvent::class,
		TwoFactorProviderForUserRegistered::class,
		TwoFactorProviderForUserUnregistered::class,
		AppPasswordCreatedEvent::class,
		LoginFlowV2GrantedEvent::class,
		TokenInvalidatedEvent::class,
	];
}
