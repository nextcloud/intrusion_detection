<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\AdminChange;

use OCA\IntrusionDetection\AdminChange\ActorResolver;
use OCP\IUser;
use OCP\IUserSession;
use Test\TestCase;

class ActorResolverTest extends TestCase {
	public function testTheUserIsTheLoggedInOneOrUnknown(): void {
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn('alice');
		$session = $this->createMock(IUserSession::class);
		$session->method('getUser')->willReturnOnConsecutiveCalls($user, null);
		$actors = new ActorResolver($session);

		$this->assertSame('alice', $actors->user());
		$this->assertSame(ActorResolver::UNKNOWN, $actors->user());
	}

	public function testOnTheCommandLineTheActorIsTheProcess(): void {
		$actors = new ActorResolver($this->createMock(IUserSession::class));
		// PHPUnit runs on the command line, without occ's OC_CONSOLE.
		$this->assertSame(defined('OC_CONSOLE') ? ActorResolver::OCC : ActorResolver::CRON, $actors->actor());
	}
}
