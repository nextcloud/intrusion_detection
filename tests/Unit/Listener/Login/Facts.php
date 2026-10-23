<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Listener\Login;

use OCA\IntrusionDetection\Listener\Login\LoginFacts;
use OCA\IntrusionDetection\Login\LoginKind;
use OCA\IntrusionDetection\Login\RequestContext;
use OCA\IntrusionDetection\Net\SourceKey;
use OCP\IUser;
use OCP\User\Events\UserLoggedInEvent;
use OCP\User\Events\UserLoggedInWithCookieEvent;

/**
 * The facts of a login for one step's test.
 */
final class Facts {
	public static function of(IUser $user, LoginKind $kind, ?RequestContext $context = null, ?bool $first = true, bool $bypass = false, bool $resumable = false, string $source = '203.0.113.5'): LoginFacts {
		$event = match ($kind) {
			LoginKind::RememberMeCookie => new UserLoggedInWithCookieEvent($user, $user->getUID(), null),
			LoginKind::AppPasswordBasic, LoginKind::Bearer, LoginKind::RestoredSession => new UserLoggedInEvent($user, $user->getUID(), 'app', true),
			LoginKind::Sso => new UserLoggedInEvent($user, $user->getUID(), null, false),
			default => new UserLoggedInEvent($user, $user->getUID(), 'secret', false),
		};
		return new LoginFacts(
			$event,
			$kind,
			$user,
			SourceKey::fromIp($source),
			'Mozilla/5.0',
			$context ?? new RequestContext(),
			static fn (): ?bool => $first,
			static fn (): bool => $bypass,
			static fn (): bool => $resumable,
		);
	}
}
