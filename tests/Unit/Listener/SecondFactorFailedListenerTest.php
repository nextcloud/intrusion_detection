<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Listener;

use OCA\IntrusionDetection\Check\Checks\SecondFactorFailedDetector;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Listener\SecondFactorFailedListener;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\SourceKey;
use OCP\Authentication\TwoFactorAuth\IProvider;
use OCP\Authentication\TwoFactorAuth\TwoFactorProviderChallengeFailed;
use OCP\IRequest;
use OCP\IUser;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;
use Test\TestCase;

class SecondFactorFailedListenerTest extends TestCase {
	/** @var Settings&MockObject */
	private Settings $settings;
	/** @var RemoteAddressResolver&MockObject */
	private RemoteAddressResolver $addresses;
	/** @var SecondFactorFailedDetector&MockObject */
	private SecondFactorFailedDetector $detector;
	/** @var LoggerInterface&MockObject */
	private LoggerInterface $logger;
	private SecondFactorFailedListener $listener;

	protected function setUp(): void {
		parent::setUp();
		$this->settings = $this->createMock(Settings::class);
		$this->addresses = $this->createMock(RemoteAddressResolver::class);
		$this->addresses->method('current')->willReturn(SourceKey::fromIp('198.51.100.7'));
		$this->detector = $this->createMock(SecondFactorFailedDetector::class);
		$this->logger = $this->createMock(LoggerInterface::class);
		$request = $this->createMock(IRequest::class);
		$request->method('getHeader')->willReturn('Firefox');
		$this->listener = new SecondFactorFailedListener($this->settings, $this->addresses, $this->detector, $request, $this->logger);
	}

	public function testTheFailureIsHandedToTheDetectorWithTheProvider(): void {
		$this->settings->method('isEnabled')->willReturn(true);
		$this->detector->expects($this->once())->method('detect')
			->with($this->isInstanceOf(IUser::class), 'backup_codes', 'Backup code', $this->callback(static fn (SourceKey $s): bool => $s->ip === '198.51.100.7'), 'Firefox');
		$this->listener->handle($this->event('backup_codes', 'Backup code'));
	}

	public function testNothingRunsWhileTheAppIsSwitchedOff(): void {
		$this->settings->method('isEnabled')->willReturn(false);
		$this->detector->expects($this->never())->method('detect');
		$this->listener->handle($this->event('totp', 'TOTP'));
	}

	public function testAllowlistedAddressesAreIgnored(): void {
		$this->settings->method('isEnabled')->willReturn(true);
		$this->addresses->method('isBypassListed')->willReturn(true);
		$this->detector->expects($this->never())->method('detect');
		$this->listener->handle($this->event('totp', 'TOTP'));
	}

	public function testAFailureIsLoggedAndNeverBreaksTheChallengePage(): void {
		$this->settings->method('isEnabled')->willReturn(true);
		$this->detector->method('detect')->willThrowException(new \RuntimeException('database gone'));
		$this->logger->expects($this->once())->method('error');
		$this->listener->handle($this->event('totp', 'TOTP'));
	}

	private function event(string $id, string $name): TwoFactorProviderChallengeFailed {
		$provider = $this->createMock(IProvider::class);
		$provider->method('getId')->willReturn($id);
		$provider->method('getDisplayName')->willReturn($name);
		return new TwoFactorProviderChallengeFailed($this->createMock(IUser::class), $provider);
	}
}
