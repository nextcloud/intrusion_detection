<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\SessionState;

use OC\Core\Controller\CssController;
use OC\Core\Controller\LoginController;
use OC\Core\Controller\TwoFactorChallengeController;
use OC\Session\Memory;
use OCA\IntrusionDetection\Confirm\LoginDetections;
use OCA\IntrusionDetection\Confirm\SecondFactorSetup;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCA\IntrusionDetection\Controller\NoticeController;
use OCA\IntrusionDetection\Controller\PasswordChangeController;
use OCA\IntrusionDetection\Controller\VerifyController;
use OCA\IntrusionDetection\Login\SessionMarkers;
use OCA\IntrusionDetection\Response\PasswordChangeFlag;
use OCA\IntrusionDetection\SessionState\ISessionStateRule;
use OCA\IntrusionDetection\SessionState\RequestTarget;
use OCA\IntrusionDetection\SessionState\Rules\LoginNoticeRule;
use OCA\IntrusionDetection\SessionState\Rules\PasswordChangeRule;
use OCA\IntrusionDetection\SessionState\Rules\StepUpRule;
use OCP\AppFramework\Controller;
use OCP\AppFramework\OCSController;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Authentication\TwoFactorAuth\ALoginSetupController;
use OCP\IRequest;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\IUserSession;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Test\TestCase;

/**
 * Which pages of the login flow each session rule lets through, for a
 * browser that opens them: the verify page, core's second-factor
 * challenge and setup, logging out, the password page, the security
 * notice, the styles every page needs, and everything else.
 */
class LoginFlowExemptionsTest extends TestCase {
	private const NOW = 1_800_000_000;
	private const PASS = 'pass';

	private SessionMarkers $state;
	private bool $setupRequired = false;

	protected function setUp(): void {
		parent::setUp();
		$this->state = new SessionMarkers(new Memory(), $this->createMock(LoggerInterface::class));
	}

	/**
	 * The pages, in the order of the expected answers.
	 *
	 * @return array<string, array{0: class-string<Controller>, 1: string, 2: string}>
	 */
	private static function pages(): array {
		return [
			'verify page' => [VerifyController::class, 'show', 'GET'],
			'verify code' => [VerifyController::class, 'confirm', 'POST'],
			'second-factor challenge' => [TwoFactorChallengeController::class, 'showChallenge', 'GET'],
			'second-factor setup' => [ALoginSetupController::class, 'setup', 'GET'],
			'log out' => [LoginController::class, 'logout', 'GET'],
			'login form' => [LoginController::class, 'showLoginForm', 'GET'],
			'password page' => [PasswordChangeController::class, 'show', 'GET'],
			'security notice' => [NoticeController::class, 'show', 'GET'],
			'styles' => [CssController::class, 'getCss', 'GET'],
			'OCS' => [OCSController::class, 'index', 'GET'],
			'any other page' => [Controller::class, 'index', 'GET'],
			'WebDAV' => ['', 'PROPFIND', 'PROPFIND'],
		];
	}

	/**
	 * What each rule answers per page: "pass", or the error it blocks with.
	 *
	 * @return iterable<string, array{0: string, 1: bool, 2: list<string>}>
	 */
	public static function rules(): iterable {
		$step = StepUpRule::ERROR;
		$refused = StepUpRule::ERROR_REFUSED;
		$client = StepUpRule::ERROR_CLIENT_ONLY;
		$password = PasswordChangeRule::ERROR;
		$notice = 'security_notice';
		$p = self::PASS;
		//                                                                     verify     code       challenge  setup      logout     login      password   notice     styles     OCS        other      WebDAV
		yield 'a pending login' => ['pending', false, [$p, $p, $p, $step, $p, $step, $step, $step, $p, $step, $step, $step]];
		yield 'a pending login that core holds at the setup' => ['pending', true, [$p, $p, $p, $p, $p, $step, $step, $step, $p, $step, $step, $step]];
		yield 'a refused login' => ['refused', false, [$p, $refused, $refused, $refused, $p, $refused, $refused, $refused, $p, $refused, $refused, $refused]];
		yield 'a refused app' => ['refused_client', false, [$step, $step, $step, $step, $step, $step, $step, $step, $step, $step, $step, $step]];
		yield 'a session for apps only' => ['client_only', false, [$client, $client, $client, $client, $p, $client, $client, $client, $p, $p, $client, $p]];
		yield 'a new password to choose' => ['password_change', false, [$p, $p, $p, $p, $p, $password, $p, $password, $p, $password, $password, $password]];
		yield 'a security notice to show' => ['notice', false, [$p, $p, $p, $p, $p, $p, $p, $p, $p, $notice, $notice, $p]];
	}

	/**
	 * @param list<string> $expected
	 */
	#[\PHPUnit\Framework\Attributes\DataProvider('rules')]
	public function testEachRuleLetsItsLoginFlowPagesThrough(string $marker, bool $setupRequired, array $expected): void {
		$this->setupRequired = $setupRequired;
		$answers = [];
		foreach (self::pages() as $name => [$class, $method, $httpMethod]) {
			$this->state = new SessionMarkers(new Memory(), $this->createMock(LoggerInterface::class));
			$rule = $this->mark($marker);
			$block = $rule->check($this->state, $this->target($class, $method, $httpMethod));
			$answers[$name] = $block === null ? self::PASS : $block->error;
		}
		$this->assertSame(array_combine(array_keys(self::pages()), $expected), $answers);
	}

	private function mark(string $marker): ISessionStateRule {
		switch ($marker) {
			case 'pending':
			case 'refused':
			case 'refused_client':
				$this->state->set(SessionMarkers::STEP_UP, (new StepUpState('alice', $marker, ['flagged_source'], self::NOW - 60, $marker === 'pending' ? self::NOW + 840 : 0, '198.51.100.7', ['email_code']))->toArray());
				return $this->stepUpRule();
			case 'client_only':
				$this->state->set(SessionMarkers::CONFIRMATION, ['uid' => 'alice', 'by' => 'none', 'policies' => ['protected_account'], 'at' => self::NOW - 60, 'client' => true]);
				return $this->stepUpRule();
			case 'password_change':
				$this->state->set(SessionMarkers::PASSWORD_CHANGE, ['uid' => 'alice', 'mode' => PasswordChangeRule::MODE_REDIRECT, 'since' => self::NOW - 60]);
				$flag = $this->createMock(PasswordChangeFlag::class);
				$flag->method('isRequired')->willReturn(true);
				return new PasswordChangeRule($flag, $this->userSession(), $this->urls());
			default:
				$this->state->set(SessionMarkers::LOGIN_NOTICE, ['uid' => 'alice', 'since' => self::NOW - 60]);
				$request = $this->createMock(IRequest::class);
				$request->method('getHeader')->willReturnCallback(static fn (string $name): string => $name === 'Accept' ? 'text/html' : '');
				return new LoginNoticeRule($request, $this->urls());
		}
	}

	/**
	 * A browser request for a controller method, with the method's real
	 * attributes, or a WebDAV request.
	 *
	 * @param class-string<Controller>|'' $class
	 */
	private function target(string $class, string $method, string $httpMethod): RequestTarget {
		if ($class === '') {
			return RequestTarget::dav($httpMethod, '/remote.php/dav/files/alice/');
		}
		$controller = $this->getMockBuilder($class)->disableOriginalConstructor()->onlyMethods([])->getMock();
		return RequestTarget::app($controller, $method, $httpMethod, '/index.php/apps/files/');
	}

	private function stepUpRule(): StepUpRule {
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturn(self::NOW);
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willReturnCallback(function (string $id): object {
			if ($id === SecondFactorSetup::class) {
				$setup = $this->createMock(SecondFactorSetup::class);
				$setup->method('isRequired')->willReturn($this->setupRequired);
				return $setup;
			}
			return $this->createMock($id === LoginDetections::class ? LoginDetections::class : $id);
		});
		return new StepUpRule($this->userSession(), $this->urls(), $time, $container, $this->createMock(LoggerInterface::class));
	}

	private function userSession(): IUserSession {
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn('alice');
		$userSession = $this->createMock(IUserSession::class);
		$userSession->method('getUser')->willReturn($user);
		return $userSession;
	}

	private function urls(): IURLGenerator {
		$urls = $this->createMock(IURLGenerator::class);
		$urls->method('linkToRoute')->willReturn('/somewhere');
		return $urls;
	}
}
