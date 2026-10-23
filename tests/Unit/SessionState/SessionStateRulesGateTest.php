<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\SessionState;

use OCA\IntrusionDetection\Check\Checks\TokenConcurrentUse\CredentialUse;
use OCA\IntrusionDetection\Check\Checks\TokenConcurrentUse\CredentialUseResolver;
use OCA\IntrusionDetection\Check\Checks\TokenConcurrentUse\PresentedCredential;
use OCA\IntrusionDetection\Login\RequestContext;
use OCA\IntrusionDetection\Login\SessionMarkers;
use OCA\IntrusionDetection\SessionState\ISessionStateRule;
use OCA\IntrusionDetection\SessionState\RequestTarget;
use OCA\IntrusionDetection\SessionState\Rules;
use OCA\IntrusionDetection\SessionState\SessionStateRules;
use OCP\IRequest;
use OCP\ISession;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Test\TestCase;

/**
 * A request that no rule would look at builds no rule.
 */
class SessionStateRulesGateTest extends TestCase {
	private RequestContext $context;
	private IRequest $request;
	/** @var array<string, mixed> */
	private array $session = [];

	protected function setUp(): void {
		parent::setUp();
		$this->context = new RequestContext();
		$this->request = $this->createMock(IRequest::class);
		$this->request->method('getParam')->willReturnCallback(static fn (string $name): mixed => $name === '_route' ? 'files.view.index' : null);
		$this->request->method('getHeader')->willReturn('');
	}

	public function testTheGateKnowsEveryRule(): void {
		$this->assertSame([
			Rules\StepUpRule::class,
			Rules\PasswordChangeRule::class,
			Rules\CredentialUseRule::class,
			Rules\LoginHistoryRule::class,
			Rules\LoginNoticeRule::class,
			Rules\DirectoryScrapingRule::class,
		], SessionStateRules::RULES, 'a new rule must be added to SessionStateRules::nothingToCheck() too');
	}

	public function testAPlainRequestBuildsNoRule(): void {
		$container = $this->createMock(ContainerInterface::class);
		$container->expects($this->never())->method('get');
		$rules = new SessionStateRules($container, $this->createMock(LoggerInterface::class), $this->context, $this->request);
		$this->assertNull($rules->check($this->state(), RequestTarget::dav('PUT', '/remote.php/dav/files/alice/a.txt')));
		$this->assertNull($rules->check($this->state(), RequestTarget::dav('PROPFIND', '/remote.php/dav/files/alice/')));
	}

	/**
	 * @return iterable<string, array{0: \Closure(self): RequestTarget}>
	 */
	public static function busyRequests(): iterable {
		yield 'session state' => [static function (self $test): RequestTarget {
			$test->session[SessionMarkers::SESSION_KEY] = [SessionMarkers::LOGIN_NOTICE => ['since' => 1]];
			return RequestTarget::dav('PROPFIND', '/remote.php/dav/files/alice/');
		}];
		yield 'a credential to learn about' => [static function (self $test): RequestTarget {
			$test->context->set(CredentialUseResolver::CONTEXT_KEY, new CredentialUse(PresentedCredential::SCHEME_BASIC, true));
			return RequestTarget::dav('PROPFIND', '/remote.php/dav/files/alice/');
		}];
		yield 'a read of the user directory' => [static fn (self $test): RequestTarget => RequestTarget::dav('PROPFIND', '/remote.php/dav/addressbooks/users/alice/z-server-generated--system/')];
	}

	/**
	 * @param \Closure(self): RequestTarget $prepare
	 */
	#[\PHPUnit\Framework\Attributes\DataProvider('busyRequests')]
	public function testRequestsWithSomethingForARuleRunTheRules(\Closure $prepare): void {
		$target = $prepare($this);
		$rule = $this->createMock(ISessionStateRule::class);
		$container = $this->createMock(ContainerInterface::class);
		$container->expects($this->exactly(count(SessionStateRules::RULES)))->method('get')->willReturn($rule);
		$rules = new SessionStateRules($container, $this->createMock(LoggerInterface::class), $this->context, $this->request);
		$this->assertNull($rules->check($this->state(), $target));
	}

	public function testAWebDavRequestWithNothingForARuleBuildsNeitherARuleNorItsTarget(): void {
		$container = $this->createMock(ContainerInterface::class);
		$container->expects($this->never())->method('get');
		$rules = new SessionStateRules($container, $this->createMock(LoggerInterface::class), $this->context, $this->request);
		$this->assertNull($rules->checkDav($this->state(), 'propfind', '/remote.php/dav/files/alice/'));
		$this->assertNull($rules->checkDav($this->state(), 'PUT', '/remote.php/dav/files/alice/a.txt'));
	}

	/**
	 * @param \Closure(self): RequestTarget $prepare
	 */
	#[\PHPUnit\Framework\Attributes\DataProvider('busyRequests')]
	public function testWebDavRequestsWithSomethingForARuleRunTheRules(\Closure $prepare): void {
		$target = $prepare($this);
		$rule = $this->createMock(ISessionStateRule::class);
		$container = $this->createMock(ContainerInterface::class);
		$container->expects($this->exactly(count(SessionStateRules::RULES)))->method('get')->willReturn($rule);
		$rules = new SessionStateRules($container, $this->createMock(LoggerInterface::class), $this->context, $this->request);
		$this->assertNull($rules->checkDav($this->state(), strtolower($target->httpMethod), $target->uri));
	}

	private function state(): SessionMarkers {
		$session = $this->createMock(ISession::class);
		$session->method('get')->willReturnCallback(fn (string $key): mixed => $this->session[$key] ?? null);
		return new SessionMarkers($session, $this->createMock(LoggerInterface::class));
	}
}
