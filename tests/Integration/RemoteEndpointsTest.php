<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Confirm\ConfirmationStatus;
use OCA\IntrusionDetection\Dav\RemoteSessionCheck;
use OCA\IntrusionDetection\Login\RequestContext;
use OCA\IntrusionDetection\Response\AccountProtection;
use OCA\IntrusionDetection\SessionState\Rules\StepUpRule;
use OCA\IntrusionDetection\SessionState\SessionGate;
use OCA\IntrusionDetection\SessionState\SessionStateRules;
use OCP\IUser;
use OCP\Server;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;
use Sabre\DAV\Exception\NotAuthenticated;

/**
 * A login that waits for its confirmation, or was refused, reaches nothing
 * on remote.php, also where no WebDAV plugin of the app runs: an endpoint
 * that lets no app add plugins, or a service another app serves there.
 */
#[Group('DB')]
class RemoteEndpointsTest extends StepUpTestCase {
	private IUser $alice;
	private RequestContext $context;
	private string $scriptName = '/index.php';
	private string $requestUri = '/index.php/apps/files/';

	protected function setUp(): void {
		parent::setUp();
		$this->alice = $this->user('ids-remote', 'alice@example.com');
		Server::get(AccountProtection::class)->protect($this->alice->getUID(), time() + 3600);
		$this->context = new RequestContext();
		$this->request->method('getScriptName')->willReturnCallback(fn (): string => $this->scriptName);
	}

	/**
	 * @return array<string, array{string}>
	 */
	public static function services(): array {
		$services = array_map(static fn (string $service): array => [$service], array_keys(DavEntryPointsTest::endpoints()));
		return array_combine(array_column($services, 0), $services) + ['an app\'s own service' => ['someapp']];
	}

	#[DataProvider('services')]
	public function testAWaitingLoginIsRefusedBeforeTheEndpointRuns(string $service): void {
		$this->login($this->alice);
		$this->assertSame(ConfirmationStatus::Pending, $this->stepUp()?->status);

		$this->remoteRequest($service);
		$block = $this->check()->atBoot();

		$this->assertNotNull($block, 'Refused before the endpoint builds its server');
		$this->assertSame(StepUpRule::DAV_HEADER, $block->davHeader);
		$this->assertSame(ConfirmationStatus::Pending, $this->stepUp()?->status, 'Still waiting: the browser can confirm it');
	}

	public function testARefusedLoginIsRefusedBeforeTheEndpointRuns(): void {
		$this->settingsEditor()->setGlobal(\OCA\IntrusionDetection\Confirm\StepUpPolicy::ProtectedAccount->settingKey(), 'refuse');
		$bob = $this->user('ids-remote-refused', null);
		Server::get(AccountProtection::class)->protect($bob->getUID(), time() + 3600);
		$this->login($bob);
		$this->assertSame(ConfirmationStatus::Refused, $this->stepUp()?->status);

		$this->remoteRequest('carddav');

		$this->assertNotNull($this->check()->atBoot());
	}

	public function testOtherSessionsAndOtherEntryPointsAreLeftToTheRules(): void {
		$this->remoteRequest('caldav');
		$this->sessionUser = $this->alice;
		$this->assertNull($this->check()->atBoot(), 'Nothing waits');

		$this->scriptName = '/index.php';
		$this->requestUri = '/index.php/apps/files/';
		$this->login($this->alice);
		$this->assertNull($this->check()->atBoot(), 'Pages are the middleware\'s');
	}

	public function testAnAppRefusedAtItsLoginIsRefusedWhereNoPluginRuns(): void {
		$this->basicAuth($this->alice);
		$this->remoteRequest('carddav');

		try {
			$this->login($this->alice);
			$this->fail('The login must not reach the address book');
		} catch (NotAuthenticated $e) {
			$this->assertSame(StepUpRule::MESSAGE_CLIENT, $e->getMessage());
		}
		$this->assertSame(ConfirmationStatus::RefusedClient, $this->stepUp()?->status);
	}

	public function testWhereThePluginRunsItAnswersTheRefusedApp(): void {
		$this->basicAuth($this->alice);
		$this->remoteRequest('dav');
		$this->context->set(RemoteSessionCheck::PLUGINS_ADDED, true);

		$this->login($this->alice);

		$this->assertSame(ConfirmationStatus::RefusedClient, $this->stepUp()?->status);
	}

	public function testAppsOutsideRemotePhpAreLeftToTheMiddleware(): void {
		$this->basicAuth($this->alice);
		$this->scriptName = '/ocs/v2.php';

		$this->login($this->alice);

		$this->assertSame(ConfirmationStatus::RefusedClient, $this->stepUp()?->status);
	}

	#[\Override]
	protected function requestContext(): RequestContext {
		return $this->context;
	}

	private function remoteRequest(string $service): void {
		$this->scriptName = '/remote.php';
		$this->requestUri = '/remote.php/' . $service . '/addressbooks/users/' . $this->alice->getUID() . '/contacts?export';
		$this->method = 'GET';
	}

	private function check(): RemoteSessionCheck {
		$request = $this->createMock(\OCP\IRequest::class);
		$request->method('getScriptName')->willReturnCallback(fn (): string => $this->scriptName);
		$request->method('getRequestUri')->willReturnCallback(fn (): string => $this->requestUri);
		$request->method('getMethod')->willReturnCallback(fn (): string => $this->method);
		$request->method('getHeader')->willReturn('');
		$rules = new SessionStateRules(new OverridingContainer([StepUpRule::class => $this->rule()]), Server::get(LoggerInterface::class), $this->context, $request);
		return new RemoteSessionCheck($request, new SessionGate($rules, $this->state, $this->userSession, $request, Server::get(LoggerInterface::class)), $this->state);
	}
}
