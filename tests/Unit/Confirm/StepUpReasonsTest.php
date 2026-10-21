<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Confirm;

use OCA\IntrusionDetection\Confirm\IStepUpReason;
use OCA\IntrusionDetection\Confirm\LoginContext;
use OCA\IntrusionDetection\Confirm\Reasons\BreachedPasswordReason;
use OCA\IntrusionDetection\Confirm\Reasons\FlaggedSourceReason;
use OCA\IntrusionDetection\Confirm\Reasons\ProtectedAccountReason;
use OCA\IntrusionDetection\Confirm\Reasons\RiskHighReason;
use OCA\IntrusionDetection\Confirm\Reasons\RiskyNetworkReason;
use OCA\IntrusionDetection\Confirm\Reasons\SprayedPasswordReason;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Confirm\StepUpReasons;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\TrustedNetwork\ITrustedNetworks;
use OCP\IUser;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Test\TestCase;

/**
 * Collecting the reasons of a login: in order, each policy once, and a
 * broken provider does not stop the others.
 */
class StepUpReasonsTest extends TestCase {
	public function testTheReasonsThatApplyAreCollectedAndABrokenOneIsSkipped(): void {
		$applies = $this->createMock(IStepUpReason::class);
		$applies->method('applies')->willReturn(true);
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willReturnCallback(static function (string $class) use ($applies): object {
			if ($class === FlaggedSourceReason::class) {
				throw new \RuntimeException('database gone');
			}
			return $applies;
		});
		$logger = $this->createMock(LoggerInterface::class);
		$logger->expects($this->once())->method('error');
		$reasons = new StepUpReasons($container, $logger);
		$this->assertSame(
			[StepUpPolicy::SprayedPassword, StepUpPolicy::ProtectedAccount, StepUpPolicy::BreachedPassword, StepUpPolicy::RiskyNetwork, StepUpPolicy::RiskHigh, StepUpPolicy::Lockdown],
			$reasons->collect($this->login()),
		);
	}

	public function testAFlaggedSourceIsOnlyReadForALoginWithAnAddressAndTheTrustOnlyWhenFlagged(): void {
		$flags = $this->createMock(FlaggedSources::class);
		$trusted = $this->createMock(ITrustedNetworks::class);
		$flags->expects($this->once())->method('sourceFlag')->willReturn(null);
		$trusted->expects($this->never())->method('isTrusted');
		$reason = new FlaggedSourceReason($flags, $trusted);
		$this->assertFalse($reason->applies($this->login(false)));
		$this->assertFalse($reason->applies($this->login()));
	}

	public function testEveryProviderNamesItsPolicyWithoutBeingBuilt(): void {
		$this->assertSame(StepUpPolicy::FlaggedSource, FlaggedSourceReason::policy());
		$this->assertSame(StepUpPolicy::SprayedPassword, SprayedPasswordReason::policy());
		$this->assertSame(StepUpPolicy::ProtectedAccount, ProtectedAccountReason::policy());
		$this->assertSame(StepUpPolicy::BreachedPassword, BreachedPasswordReason::policy());
		$this->assertSame(StepUpPolicy::RiskyNetwork, RiskyNetworkReason::policy());
		$this->assertSame(StepUpPolicy::RiskHigh, RiskHighReason::policy());
	}

	private function login(bool $withAddress = true): LoginContext {
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn('alice');
		return new LoginContext($user, $withAddress ? SourceKey::fromIp('198.51.100.7') : null, true, null, [], false);
	}
}
