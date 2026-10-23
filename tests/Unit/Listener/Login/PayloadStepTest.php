<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Listener\Login;

use OCA\IntrusionDetection\Check\Checks\InjectionProbe\PayloadHit;
use OCA\IntrusionDetection\Check\Checks\InjectionProbe\PayloadResponder;
use OCA\IntrusionDetection\Check\Checks\InjectionProbe\PendingHit;
use OCA\IntrusionDetection\Guard\DeferredHits;
use OCA\IntrusionDetection\Listener\Login\PayloadStep;
use OCA\IntrusionDetection\Login\LoginKind;
use OCA\IntrusionDetection\Login\RequestContext;
use OCA\IntrusionDetection\Net\SourceKey;
use OCP\IUser;
use Test\TestCase;

class PayloadStepTest extends TestCase {
	public function testOnlyAPendingHitOfALoginThatIsNoCookieApplies(): void {
		$user = $this->createMock(IUser::class);
		$context = new RequestContext();
		$this->assertFalse(PayloadStep::appliesTo(Facts::of($user, LoginKind::AppPasswordBasic, $context)), 'nothing pending');

		$context->set(PayloadResponder::CONTEXT_KEY, new PendingHit(
			new PayloadHit(PayloadHit::LOCATION_QUERY, 'id', ['sql_union_select' => 3], 3, 3, 'none', 'x'),
			SourceKey::fromIp('198.51.100.1'),
			PendingHit::CREDENTIAL_BASIC,
			null,
		));
		$this->assertTrue(PayloadStep::appliesTo(Facts::of($user, LoginKind::AppPasswordBasic, $context)));
		$this->assertFalse(PayloadStep::appliesTo(Facts::of($user, LoginKind::RememberMeCookie, $context)));
	}

	public function testTheLoginDecidesTheWaitingHits(): void {
		$user = $this->createMock(IUser::class);
		$hits = $this->createMock(DeferredHits::class);
		$hits->expects($this->once())->method('resolve')->with($user);
		(new PayloadStep($hits))->handle(Facts::of($user, LoginKind::AppPasswordBasic));
	}
}
