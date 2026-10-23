<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Takeover;

use OC\Session\Memory;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCA\IntrusionDetection\Login\CoreSession;
use OCA\IntrusionDetection\Login\SessionMarkers;
use OCA\IntrusionDetection\Takeover\IRiskyLoginSignal;
use OCA\IntrusionDetection\Takeover\RiskyLogin;
use OCA\IntrusionDetection\Takeover\RiskyLogins;
use OCA\IntrusionDetection\Takeover\Signals\RiskyNetworkSignal;
use OCA\IntrusionDetection\Takeover\Signals\UnconfirmedLoginSignal;
use OCA\IntrusionDetection\Takeover\Signals\UnknownDeviceSignal;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Test\TestCase;

/**
 * What makes a login risky for the takeover check.
 */
class RiskyLoginsTest extends TestCase {
	public function testALoginLetInWithoutConfirmationIsRisky(): void {
		$signal = $this->signal(['uid' => 'alice', 'by' => 'none', 'policies' => ['flagged_source'], 'at' => 1000], 7);
		$login = $signal->riskyLogin('alice', 7);
		$this->assertNotNull($login);
		$this->assertSame(1000, $login->at);
		$this->assertSame(RiskyLogin::REASON_UNCONFIRMED, $login->reason);
		$this->assertSame(['flagged_source'], $login->policies);
	}

	public function testALoginThatStillWaitsForItsConfirmationIsRisky(): void {
		$signal = $this->signal(null, 7, new StepUpState('alice', StepUpState::PENDING, ['protected_account'], 900, 1800));
		$login = $signal->riskyLogin('alice', 7);
		$this->assertSame(900, $login?->at);
		$this->assertSame(RiskyLogin::REASON_UNCONFIRMED, $login->reason);
		$this->assertSame(['protected_account'], $login->policies);
		$this->assertNull($signal->riskyLogin('bob', 7));
	}

	public function testAConfirmedLoginIsNot(): void {
		foreach (['second_factor', 'email_code'] as $by) {
			$this->assertNull($this->signal(['uid' => 'alice', 'by' => $by, 'policies' => ['flagged_source'], 'at' => 1000], 7)->riskyLogin('alice', 7), $by);
		}
		$this->assertNull($this->signal(null, 7)->riskyLogin('alice', 7), 'A login without reasons');
	}

	public function testOnlyTheCurrentSessionOfTheAccountIsJudged(): void {
		$marker = ['uid' => 'alice', 'by' => 'none', 'policies' => [], 'at' => 1000];
		$this->assertNull($this->signal($marker, 7)->riskyLogin('bob', 7), 'Another account');
		$this->assertNull($this->signal($marker, 7)->riskyLogin('alice', 8), 'Another session');
		$this->assertNull($this->signal($marker, 7)->riskyLogin('alice', null));
	}

	public function testTheEarliestSignalWinsAndAFailingOneIsIgnored(): void {
		$late = $this->createMock(IRiskyLoginSignal::class);
		$late->method('riskyLogin')->willReturn(new RiskyLogin(2000, RiskyLogin::REASON_RISKY_NETWORK));
		$broken = $this->createMock(IRiskyLoginSignal::class);
		$broken->method('riskyLogin')->willThrowException(new \RuntimeException('boom'));
		$early = $this->createMock(IRiskyLoginSignal::class);
		$early->method('riskyLogin')->willReturn(new RiskyLogin(1000, RiskyLogin::REASON_UNCONFIRMED));
		$none = $this->createMock(IRiskyLoginSignal::class);
		$none->method('riskyLogin')->willReturn(null);
		$byName = ['late' => $late, 'broken' => $broken, 'early' => $early, 'none' => $none];
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willReturnCallback(static fn (string $id): IRiskyLoginSignal => $byName[$id]);
		$logger = $this->createMock(LoggerInterface::class);
		$logger->expects($this->once())->method('error');

		$logins = new class($container, $logger) extends RiskyLogins {
			protected function signals(): array {
				/** @var list<class-string<IRiskyLoginSignal>> */
				return ['late', 'broken', 'early', 'none'];
			}
		};
		$this->assertSame(1000, $logins->of('alice', 7)?->at, 'The window starts at the earliest risky login');
		$this->assertSame([UnconfirmedLoginSignal::class, UnknownDeviceSignal::class, RiskyNetworkSignal::class], RiskyLogins::SIGNALS);
	}

	/**
	 * @param ?array<string, mixed> $marker
	 */
	private function signal(?array $marker, int $currentToken, ?StepUpState $stepUp = null): UnconfirmedLoginSignal {
		$session = new Memory();
		$state = new SessionMarkers($session, $this->createMock(LoggerInterface::class));
		if ($stepUp !== null) {
			$state->set(SessionMarkers::STEP_UP, $stepUp->toArray());
		}
		if ($marker !== null) {
			$state->set(SessionMarkers::CONFIRMATION, $marker);
		}
		$current = $this->createMock(CoreSession::class);
		$current->method('tokenId')->willReturn($currentToken);
		return new UnconfirmedLoginSignal($state, $current);
	}
}
