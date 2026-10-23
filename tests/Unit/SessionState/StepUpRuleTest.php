<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\SessionState;

use OC\Core\Controller\CssController;
use OC\Core\Controller\GuestAvatarController;
use OC\Core\Controller\JsController;
use OC\Core\Controller\LoginController;
use OC\Core\Controller\OCJSController;
use OC\Core\Controller\TwoFactorChallengeController;
use OC\Session\Memory;
use OCA\IntrusionDetection\Check\Checks\StepUpFailed\StepUpFailed;
use OCA\IntrusionDetection\Confirm\ConfirmationStatus;
use OCA\IntrusionDetection\Confirm\LoginConfirmations;
use OCA\IntrusionDetection\Confirm\LoginDetections;
use OCA\IntrusionDetection\Confirm\SecondFactorSetup;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCA\IntrusionDetection\Controller\PasswordChangeController;
use OCA\IntrusionDetection\Controller\VerifyController;
use OCA\IntrusionDetection\Login\SessionMarkers;
use OCA\IntrusionDetection\SessionState\RequestTarget;
use OCA\IntrusionDetection\SessionState\Rules\PasswordChangeRule;
use OCA\IntrusionDetection\SessionState\Rules\StepUpRule;
use OCA\IntrusionDetection\SessionState\SessionStateRules;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Authentication\TwoFactorAuth\ALoginSetupController;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\IUserSession;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Test\TestCase;

/**
 * The session rule of a login that waits for its confirmation, was
 * refused, or came back without its state (concept section 11.5).
 */
class StepUpRuleTest extends TestCase {
	private SessionMarkers $state;
	private int $now = 1_800_000_000;
	/** @var LoginConfirmations&MockObject */
	private LoginConfirmations $service;
	/** @var LoginDetections&MockObject */
	private LoginDetections $linker;
	private bool $serviceLoaded = false;
	private bool $setupRequired = false;

	protected function setUp(): void {
		parent::setUp();
		$this->state = new SessionMarkers(new Memory(), $this->createMock(LoggerInterface::class));
		$this->service = $this->createMock(LoginConfirmations::class);
		$this->linker = $this->createMock(LoginDetections::class);
	}

	public function testNothingPendingPassesWithoutLoadingAnything(): void {
		$this->assertNull($this->rule()->check($this->state, $this->target(Controller::class)));
		$this->assertNull($this->rule()->check($this->state, RequestTarget::dav('PROPFIND', '/remote.php/dav/files/alice/')));
		$this->assertFalse($this->serviceLoaded, 'No service is built while nothing is pending');
	}

	public function testAPendingLoginSendsBrowsersToTheVerifyPage(): void {
		$this->pending();
		$block = $this->rule()->check($this->state, $this->target(Controller::class));
		$this->assertNotNull($block);
		$this->assertSame(StepUpRule::ERROR, $block->error);
		$this->assertSame(StepUpRule::DAV_HEADER, $block->davHeader);
		$this->assertSame('/verify?redirect_url=/index.php/apps/files/', $block->redirectUrl);
	}

	public function testWebDavIsRefusedWithTheHeader(): void {
		$this->pending();
		$block = $this->rule()->check($this->state, RequestTarget::dav('PROPFIND', '/remote.php/dav/files/alice/'));
		$this->assertSame('X-Nextcloud-Step-Up', $block?->davHeader);
		$this->assertSame(StepUpRule::MESSAGE_PENDING, $block->message);
	}

	public function testWebDavIsToldWhyALoginWasRefusedOrEnded(): void {
		$dav = RequestTarget::dav('PROPFIND', '/remote.php/dav/files/alice/');
		$this->state->set(SessionMarkers::STEP_UP, (new StepUpState('alice', ConfirmationStatus::Refused, ['flagged_source'], $this->now, 0))->toArray());
		$this->assertSame(StepUpRule::MESSAGE_REFUSED, $this->rule()->check($this->state, $dav)?->message);
		$this->state->set(SessionMarkers::STEP_UP, (new StepUpState('alice', ConfirmationStatus::RefusedClient, ['protected_account'], $this->now, 0))->toArray());
		$this->assertSame(StepUpRule::MESSAGE_CLIENT, $this->rule()->check($this->state, $dav)?->message);
		$this->pending(deadline: $this->now);
		$this->assertSame(StepUpRule::MESSAGE_ENDED, $this->rule()->check($this->state, $dav)?->message);
	}

	public function testOnlyThePublicResourcesEveryPageNeedsStayReachable(): void {
		$this->pending();
		foreach ([CssController::class => 'getCss', JsController::class => 'getJs', OCJSController::class => 'getConfig'] as $class => $method) {
			$this->assertNull($this->rule()->check($this->state, $this->publicTarget($class, $method)), $class);
		}
		$this->assertNotNull($this->rule()->check($this->state, $this->publicTarget(GuestAvatarController::class, 'getAvatar')), 'Another public page');
		$this->assertNotNull($this->rule()->check($this->state, $this->publicTarget(CssController::class, 'getCss', 'POST')), 'Read-only only');
	}

	public function testThePagesThatResolveItStayReachable(): void {
		$this->pending();
		foreach ([VerifyController::class, TwoFactorChallengeController::class] as $class) {
			$this->assertNull($this->rule()->check($this->state, $this->target($class)), $class);
		}
		$this->assertNull($this->rule()->check($this->state, $this->target(LoginController::class, 'logout')));
		$this->assertNotNull($this->rule()->check($this->state, $this->target(LoginController::class, 'showLoginForm')));
		$this->assertNotNull($this->rule()->check($this->state, $this->target(PasswordChangeController::class, 'show')), 'The password page needs a confirmed login');
	}

	public function testASecondFactorCanOnlyBeSetUpWhileCoreRequiresIt(): void {
		$this->pending();
		$this->assertNotNull($this->rule()->check($this->state, $this->target(ALoginSetupController::class)), 'A pending login must not add its own second factor');
		$this->setupRequired = true;
		$this->assertNull($this->rule()->check($this->state, $this->target(ALoginSetupController::class)), 'Two factors enforced and none set up: core holds the login there');
	}

	public function testATimedOutLoginIsFailedAndEnded(): void {
		$this->pending(deadline: $this->now);
		$this->service->expects($this->once())->method('fail')->with($this->isInstanceOf(StepUpState::class), StepUpFailed::RULE_TIMEOUT);
		$block = $this->rule()->check($this->state, $this->target(VerifyController::class));
		$this->assertNotNull($block, 'Even the verify page');
		$this->assertSame('/ended?reason=timeout', $block->redirectUrl);
	}

	public function testAnErrorWhileEndingTheLoginKeepsItBlocked(): void {
		$this->pending(deadline: $this->now - 1);
		$this->service->method('fail')->willThrowException(new \RuntimeException('database gone'));
		$this->assertNotNull($this->rule()->check($this->state, $this->target(Controller::class)));
	}

	public function testAResumedSessionIsEnded(): void {
		$this->state->set(SessionMarkers::STEP_UP, (new StepUpState('alice', ConfirmationStatus::Resumed, [], $this->now, $this->now))->toArray());
		$this->service->expects($this->once())->method('fail')->with($this->anything(), StepUpFailed::RULE_RESUMED);
		$this->assertSame('/ended?reason=resumed', $this->rule()->check($this->state, $this->target(Controller::class))?->redirectUrl);
	}

	public function testARefusedLoginCanOnlyBeToldWhy(): void {
		$this->state->set(SessionMarkers::STEP_UP, (new StepUpState('alice', ConfirmationStatus::Refused, ['flagged_source'], $this->now, 0, reference: 'SAAA-AAAB'))->toArray());
		$this->assertNull($this->rule()->check($this->state, $this->target(VerifyController::class, 'show')));
		$this->assertSame(StepUpRule::ERROR_REFUSED, $this->rule()->check($this->state, $this->target(VerifyController::class, 'confirm'))?->error);
		$this->assertSame(StepUpRule::ERROR_REFUSED, $this->rule()->check($this->state, $this->target(Controller::class))?->error);
		$this->assertNotNull($this->rule()->check($this->state, $this->target(TwoFactorChallengeController::class)));
	}

	public function testARefusedAppLoginIsRefusedEverywhereWithoutARedirect(): void {
		$this->state->set(SessionMarkers::STEP_UP, (new StepUpState('alice', ConfirmationStatus::RefusedClient, ['protected_account'], $this->now, 0))->toArray());
		foreach ([Controller::class, VerifyController::class] as $class) {
			$block = $this->rule()->check($this->state, $this->target($class));
			$this->assertNotNull($block, $class);
			$this->assertNull($block->redirectUrl);
		}
	}

	public function testAMarkerOfAnotherAccountIsDropped(): void {
		$this->state->set(SessionMarkers::STEP_UP, (new StepUpState('mallory', ConfirmationStatus::Pending, [], $this->now, $this->now + 900))->toArray());
		$this->assertNull($this->rule()->check($this->state, $this->target(Controller::class)));
		$this->assertNull($this->state->get(SessionMarkers::STEP_UP));
	}

	public function testDetectionsOfTheLoginAreLinkedOnTheFirstRequest(): void {
		$this->state->set(SessionMarkers::LOGIN_DETECTIONS, ['uid' => 'alice', 'ids' => [7]]);
		$this->linker->expects($this->once())->method('linkSession')->with('alice');
		$this->assertNull($this->rule()->check($this->state, $this->target(Controller::class)));
	}

	public function testTheConfirmationComesBeforeTheForcedPasswordChange(): void {
		$this->assertSame(StepUpRule::class, SessionStateRules::RULES[0]);
		$this->assertTrue(PasswordChangeRule::isExempt($this->target(VerifyController::class)), 'Otherwise the two pages would send browsers to each other');
	}

	private function pending(?int $deadline = null): void {
		$this->state->set(SessionMarkers::STEP_UP, (new StepUpState('alice', ConfirmationStatus::Pending, ['flagged_source'], $this->now - 60, $deadline ?? $this->now + 840, '198.51.100.7', ['email_code']))->toArray());
	}

	/**
	 * @param class-string<Controller> $class
	 */
	private function target(string $class, string $method = 'index'): RequestTarget {
		$controller = $this->getMockBuilder($class)->disableOriginalConstructor()->onlyMethods([])->getMock();
		return RequestTarget::app($controller, $method, 'GET', '/index.php/apps/files/');
	}

	/**
	 * A real controller method, with its attributes.
	 *
	 * @param class-string<Controller> $class
	 */
	private function publicTarget(string $class, string $method, string $httpMethod = 'GET'): RequestTarget {
		$controller = $this->getMockBuilder($class)->disableOriginalConstructor()->onlyMethods([])->getMock();
		return RequestTarget::app($controller, $method, $httpMethod, '/index.php/css/core/server.css');
	}

	private function rule(): StepUpRule {
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn('alice');
		$userSession = $this->createMock(IUserSession::class);
		$userSession->method('getUser')->willReturn($user);
		$urls = $this->createMock(IURLGenerator::class);
		$urls->method('linkToRoute')->willReturnCallback(static fn (string $route, array $params): string => match ($route) {
			StepUpRule::ROUTE => '/verify?redirect_url=' . $params['redirect_url'],
			StepUpRule::ENDED_ROUTE => '/ended?reason=' . $params['reason'],
			default => '/',
		});
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturnCallback(fn (): int => $this->now);
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willReturnCallback(function (string $id): object {
			$this->serviceLoaded = true;
			if ($id === SecondFactorSetup::class) {
				$setup = $this->createMock(SecondFactorSetup::class);
				$setup->method('isRequired')->willReturn($this->setupRequired);
				return $setup;
			}
			return $id === LoginDetections::class ? $this->linker : $this->service;
		});
		return new StepUpRule($userSession, $urls, $time, $container, $this->createMock(LoggerInterface::class));
	}
}
