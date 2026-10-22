<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Dav;

use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Dav\FederatedShareUsePlugin;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Listener\SabrePluginAddListener;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Share\FederationPartners;
use OCP\BeforeSabrePubliclyLoadedEvent;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Sabre\DAV\Auth\Backend\BackendInterface;
use Sabre\DAV\Auth\Plugin as AuthPlugin;
use Sabre\DAV\Server as SabreServer;
use Sabre\HTTP\Request;
use Sabre\HTTP\Response;
use Test\TestCase;

class FederatedShareUsePluginTest extends TestCase {
	/**
	 * @return array<string, array{Mode, bool}>
	 */
	public static function modes(): array {
		return [
			'protect' => [Mode::Protect, true],
			'off' => [Mode::Off, false],
		];
	}

	#[DataProvider('modes')]
	public function testThePublicWebdavServerGetsThePluginWhileTheCheckRuns(Mode $mode, bool $added): void {
		$settings = $this->createMock(Settings::class);
		$settings->method('modeState')->willReturn(new ModeState($mode, $mode));
		$plugin = $this->plugin($this->createMock(FederationPartners::class));
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willReturnCallback(static fn (string $class): object => $class === Settings::class ? $settings : $plugin);

		$server = new SabreServer();
		(new SabrePluginAddListener($container, $this->createMock(LoggerInterface::class)))->handle(new BeforeSabrePubliclyLoadedEvent($server));

		$this->assertSame($added ? $plugin : null, $server->getPlugin($plugin->getPluginName()));
	}

	/**
	 * @return array<string, array{string, ?string}>
	 */
	public static function principals(): array {
		return [
			'basic auth on /public.php/webdav' => ['principals/aB3dE5fG7hJ9kL2', 'aB3dE5fG7hJ9kL2'],
			'an access token of a federated share' => ['principals/users/aB3dE5fG7hJ9kL2', 'aB3dE5fG7hJ9kL2'],
		];
	}

	#[DataProvider('principals')]
	public function testTheTokenOfTheAuthenticatedShareIsLookedAt(string $principal, string $token): void {
		$partners = $this->createMock(FederationPartners::class);
		$partners->expects($this->once())->method('observe')->with(SourceKey::fromIp('203.0.113.80'), $token);
		$this->assertTrue($this->authenticatedAs($principal, $partners));
	}

	public function testNothingIsLookedAtWithoutAuthentication(): void {
		$partners = $this->createMock(FederationPartners::class);
		$partners->expects($this->never())->method('observe');
		$this->assertTrue($this->authenticatedAs(null, $partners));
	}

	public function testAFailureNeverBreaksTheRequest(): void {
		$partners = $this->createMock(FederationPartners::class);
		$partners->method('observe')->willThrowException(new \RuntimeException('database gone'));
		$this->assertTrue($this->authenticatedAs('principals/aB3dE5fG7hJ9kL2', $partners));
	}

	private function authenticatedAs(?string $principal, FederationPartners $partners): bool {
		$backend = $this->createMock(BackendInterface::class);
		$backend->method('check')->willReturn($principal === null ? [false, 'No credentials'] : [true, $principal]);
		$server = new SabreServer();
		$auth = new AuthPlugin($backend);
		$auth->autoRequireLogin = false;
		$server->addPlugin($auth);
		$plugin = $this->plugin($partners);
		$server->addPlugin($plugin);
		$request = new Request('PROPFIND', '/');
		$response = new Response();
		$auth->beforeMethod($request, $response);
		return $plugin->beforeMethod($request, $response);
	}

	private function plugin(FederationPartners $partners): FederatedShareUsePlugin {
		$addresses = $this->createMock(RemoteAddressResolver::class);
		$addresses->method('current')->willReturn(SourceKey::fromIp('203.0.113.80'));
		return new FederatedShareUsePlugin($addresses, $partners, $this->createMock(LoggerInterface::class));
	}
}
