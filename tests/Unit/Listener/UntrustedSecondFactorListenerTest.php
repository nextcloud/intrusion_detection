<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Listener;

use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Confirm\UntrustedSecondFactors;
use OCA\IntrusionDetection\Listener\UntrustedSecondFactorListener;
use OCP\Authentication\TwoFactorAuth\IProvider;
use OCP\Authentication\TwoFactorAuth\TwoFactorProviderForUserRegistered;
use OCP\Authentication\TwoFactorAuth\TwoFactorProviderForUserUnregistered;
use OCP\IUser;
use Psr\Log\LoggerInterface;
use Test\TestCase;

class UntrustedSecondFactorListenerTest extends TestCase {
	public function testRegisteredAndUnregisteredProvidersAreHandedOn(): void {
		$untrusted = $this->createMock(UntrustedSecondFactors::class);
		$untrusted->expects($this->once())->method('registered')->with('alice', 'totp');
		$untrusted->expects($this->once())->method('unregistered')->with('alice', 'totp');
		$listener = $this->listener($untrusted, true);
		$listener->handle(new TwoFactorProviderForUserRegistered($this->user(), $this->provider()));
		$listener->handle(new TwoFactorProviderForUserUnregistered($this->user(), $this->provider()));
	}

	public function testNothingWhileTheAppIsOffAndFailuresAreLogged(): void {
		$untrusted = $this->createMock(UntrustedSecondFactors::class);
		$untrusted->expects($this->never())->method('registered');
		$this->listener($untrusted, false)->handle(new TwoFactorProviderForUserRegistered($this->user(), $this->provider()));

		$broken = $this->createMock(UntrustedSecondFactors::class);
		$broken->method('registered')->willThrowException(new \RuntimeException('db'));
		$logger = $this->createMock(LoggerInterface::class);
		$logger->expects($this->once())->method('error');
		(new UntrustedSecondFactorListener($this->settings(true), $broken, $logger))->handle(new TwoFactorProviderForUserRegistered($this->user(), $this->provider()));
	}

	private function listener(UntrustedSecondFactors $untrusted, bool $enabled): UntrustedSecondFactorListener {
		return new UntrustedSecondFactorListener($this->settings($enabled), $untrusted, $this->createMock(LoggerInterface::class));
	}

	private function settings(bool $enabled): AppSettings {
		$settings = $this->createMock(AppSettings::class);
		$settings->method('isEnabled')->willReturn($enabled);
		return $settings;
	}

	private function user(): IUser {
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn('alice');
		return $user;
	}

	private function provider(): IProvider {
		$provider = $this->createMock(IProvider::class);
		$provider->method('getId')->willReturn('totp');
		return $provider;
	}
}
