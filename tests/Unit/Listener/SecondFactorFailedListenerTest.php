<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Listener;

use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Listener\SecondFactorFailedListener;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Signal\SecondFactorFailure;
use OCA\IntrusionDetection\Signal\SignalDispatcher;
use OCP\Authentication\TwoFactorAuth\IProvider;
use OCP\Authentication\TwoFactorAuth\TwoFactorProviderChallengeFailed;
use OCP\IRequest;
use OCP\IUser;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;
use Test\TestCase;

class SecondFactorFailedListenerTest extends TestCase {
	/** @var AppSettings&MockObject */
	private AppSettings $settings;
	/** @var RemoteAddressResolver&MockObject */
	private RemoteAddressResolver $addresses;
	/** @var SignalDispatcher&MockObject */
	private SignalDispatcher $dispatcher;
	/** @var LoggerInterface&MockObject */
	private LoggerInterface $logger;
	private SecondFactorFailedListener $listener;

	protected function setUp(): void {
		parent::setUp();
		$this->settings = $this->createMock(AppSettings::class);
		$this->addresses = $this->createMock(RemoteAddressResolver::class);
		$this->addresses->method('current')->willReturn(SourceKey::fromIp('198.51.100.7'));
		$this->dispatcher = $this->createMock(SignalDispatcher::class);
		$this->logger = $this->createMock(LoggerInterface::class);
		$request = $this->createMock(IRequest::class);
		$request->method('getHeader')->willReturn('Firefox');
		$this->listener = new SecondFactorFailedListener($this->settings, $this->addresses, $this->dispatcher, $request, $this->logger);
	}

	public function testTheFailureIsHandedOnWithTheProvider(): void {
		$this->settings->method('isEnabled')->willReturn(true);
		$this->dispatcher->expects($this->once())->method('dispatch')->with($this->callback(
			static fn (SecondFactorFailure $f): bool => $f->providerId === 'backup_codes' && $f->providerName === 'Backup code' && $f->source->ip === '198.51.100.7' && $f->userAgent === 'Firefox',
		));
		$this->listener->handle($this->event('backup_codes', 'Backup code'));
	}

	public function testNothingRunsWhileTheAppIsSwitchedOff(): void {
		$this->settings->method('isEnabled')->willReturn(false);
		$this->dispatcher->expects($this->never())->method('dispatch');
		$this->listener->handle($this->event('totp', 'TOTP'));
	}

	public function testAllowlistedAddressesAreIgnored(): void {
		$this->settings->method('isEnabled')->willReturn(true);
		$this->addresses->method('isBypassListed')->willReturn(true);
		$this->dispatcher->expects($this->never())->method('dispatch');
		$this->listener->handle($this->event('totp', 'TOTP'));
	}

	public function testAFailureIsLoggedAndNeverBreaksTheChallengePage(): void {
		$this->settings->method('isEnabled')->willReturn(true);
		$this->dispatcher->method('dispatch')->willThrowException(new \RuntimeException('database gone'));
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
