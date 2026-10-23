<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Controller;

use OC\AppFramework\Middleware\Security\Exceptions\NotConfirmedException;
use OC\AppFramework\Middleware\Security\PasswordConfirmationMiddleware;
use OC\AppFramework\Utility\ControllerMethodReflector;
use OC\Authentication\Token\IProvider;
use OC\User\Manager;
use OCA\IntrusionDetection\AdminChange\ActorResolver;
use OCA\IntrusionDetection\AdminChange\ApprovalException;
use OCA\IntrusionDetection\AdminChange\ApprovalService;
use OCA\IntrusionDetection\Confirm\SessionConfirmation;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCA\IntrusionDetection\Controller\ApprovalController;
use OCA\IntrusionDetection\Db\Approval;
use OCA\IntrusionDetection\Login\CoreSession;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\NoAdminRequired;
use OCP\AppFramework\Http\Attribute\NoCSRFRequired;
use OCP\AppFramework\Http\Attribute\PublicPage;
use OCP\AppFramework\Http\Attribute\UserRateLimit;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Authentication\Exceptions\InvalidTokenException;
use OCP\IL10N;
use OCP\IRequest;
use OCP\ISession;
use OCP\IUser;
use OCP\IUserManager;
use OCP\IUserSession;
use OCP\Security\Ip\IRemoteAddress;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;
use Test\TestCase;

class ApprovalControllerTest extends TestCase {
	use AnswersLikeTheApi;

	private const NOW = 1_800_000_000;

	private IUserManager&MockObject $userManager;
	/** @var ?array<string, mixed> how the deciding administrator's own login was confirmed */
	private ?array $confirmation = null;
	/** @var ?array<string, mixed> the step-up of the deciding administrator's own session */
	private ?array $stepUp = null;
	private bool $appPassword = false;

	protected function setUp(): void {
		parent::setUp();
		$this->userManager = $this->createMock(IUserManager::class);
		$this->userManager->method('getDisplayName')->willReturnCallback(static fn (string $uid): ?string => ['alice' => 'Alice Liddell', 'bob' => 'Bob Builder'][$uid] ?? null);
	}

	/**
	 * @return array<string, array{string}>
	 */
	public static function decisions(): array {
		return ['approve' => ['approve'], 'reject' => ['reject']];
	}

	#[DataProvider('decisions')]
	public function testDecisionsAreRateLimited(string $method): void {
		$reflection = new \ReflectionMethod(ApprovalController::class, $method);
		$this->assertCount(1, $reflection->getAttributes(UserRateLimit::class));
	}

	/**
	 * @return array<string, array{string, ?int, bool}>
	 */
	public static function confirmations(): array {
		return [
			'approve, confirmed a minute ago' => ['approve', self::NOW - 60, true],
			'approve, confirmed an hour ago' => ['approve', self::NOW - 3600, false],
			'approve, never confirmed (an app password)' => ['approve', null, false],
			'reject, confirmed a minute ago' => ['reject', self::NOW - 60, true],
			'reject, never confirmed (an app password)' => ['reject', null, true],
		];
	}

	/**
	 * Approving needs a recent password confirmation, so a stolen app
	 * password alone never approves; refusing changes nothing and needs none.
	 */
	#[DataProvider('confirmations')]
	public function testOnlyApprovingNeedsARecentPasswordConfirmation(string $method, ?int $lastConfirm, bool $passes): void {
		$this->confirmation = ['uid' => 'carol', 'by' => 'second_factor', 'policies' => [], 'at' => 1];
		$approval = new Approval();
		$approval->setStatus($method === 'approve' ? Approval::STATUS_APPROVED : Approval::STATUS_REJECTED);
		$service = $this->createMock(ApprovalService::class);
		$service->expects($passes ? $this->once() : $this->never())->method($method)->with(5, 'carol', ApprovalService::VIA_WEB)->willReturn($approval);
		$controller = $this->controller($service);

		$reflector = new ControllerMethodReflector($this->createMock(LoggerInterface::class));
		$reflector->reflect($controller, $method);
		$session = $this->createMock(ISession::class);
		$session->method('get')->willReturnCallback(static fn (string $key): mixed => $key === 'last-password-confirm' ? $lastConfirm : null);
		$session->method('getId')->willReturn('session');
		$tokens = $this->createMock(IProvider::class);
		$tokens->method('getToken')->willThrowException(new InvalidTokenException());
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturn(self::NOW);
		$middleware = new PasswordConfirmationMiddleware($reflector, $session, $this->userSession(), $time, $tokens, $this->createMock(IRequest::class), $this->createMock(Manager::class), $this->createMock(IRemoteAddress::class));

		try {
			$middleware->beforeController($controller, $method);
			$this->assertTrue($passes, 'The middleware let the request through');
			$this->assertSame(Http::STATUS_OK, $controller->$method(5)->getStatus());
		} catch (NotConfirmedException) {
			$this->assertFalse($passes, 'The middleware asked for the password');
		}
	}

	public function testEveryEndpointIsForAdministratorsAndCsrfProtected(): void {
		foreach (['index', 'approve', 'reject'] as $method) {
			$reflection = new \ReflectionMethod(ApprovalController::class, $method);
			foreach ([NoAdminRequired::class, NoCSRFRequired::class, PublicPage::class] as $attribute) {
				$this->assertSame([], $reflection->getAttributes($attribute), $method . ' must not have ' . $attribute);
			}
		}
		$this->assertSame([], (new \ReflectionClass(ApprovalController::class))->getAttributes(NoAdminRequired::class));
	}

	public function testTheListLimitIsKeptWithinBounds(): void {
		$service = $this->createMock(ApprovalService::class);
		$service->expects($this->exactly(3))->method('list')
			->willReturnCallback(function (bool $pendingOnly, int $limit): array {
				$this->assertContains($limit, [1, 50, 200]);
				return [];
			});
		$controller = $this->controller($service);
		$controller->index(limit: 0);
		$controller->index(limit: 50);
		$controller->index(true, 5000);
	}

	public function testTheDecidingAdministratorIsTheLoggedInOne(): void {
		$service = $this->createMock(ApprovalService::class);
		$approval = new Approval();
		$approval->setStatus(Approval::STATUS_APPROVED);
		$service->expects($this->once())->method('approve')->with(5, 'carol', ApprovalService::VIA_WEB)->willReturn($approval);
		$response = $this->answer(fn () => $this->controller($service)->approve(5));
		$this->assertSame(Http::STATUS_OK, $response->getStatus());
		$this->assertSame(Approval::STATUS_APPROVED, $response->getData()['status']);
	}

	public function testAnAdministratorWhoseOwnLoginWasNotConfirmedCannotApprove(): void {
		$service = $this->createMock(ApprovalService::class);
		$service->expects($this->never())->method('approve');
		$this->confirmation = ['uid' => 'carol', 'by' => 'none', 'policies' => ['flagged_source'], 'at' => 1];
		$response = $this->answer(fn () => $this->controller($service)->approve(5));
		$this->assertSame(Http::STATUS_FORBIDDEN, $response->getStatus());
		$this->assertSame(ApprovalException::UNCONFIRMED, $response->getData()['reason']);

		$this->confirmation = null;
		$this->stepUp = (new StepUpState('carol', StepUpState::PENDING, ['flagged_source'], 1, 901))->toArray();
		$this->assertSame(ApprovalException::UNCONFIRMED, $this->answer(fn () => $this->controller($service)->approve(5))->getData()['reason'], 'A login that still waits for its confirmation');
		$this->stepUp = null;
		$this->appPassword = true;
		$this->assertSame(ApprovalException::UNCONFIRMED, $this->answer(fn () => $this->controller($service)->approve(5))->getData()['reason'], 'An app password');
		$this->appPassword = false;

		$this->confirmation = ['uid' => 'carol', 'by' => 'email_code', 'policies' => ['flagged_source'], 'at' => 1];
		$approval = new Approval();
		$approval->setStatus(Approval::STATUS_APPROVED);
		$other = $this->createMock(ApprovalService::class);
		$other->expects($this->once())->method('approve')->willReturn($approval);
		$this->assertSame(Http::STATUS_OK, $this->controller($other)->approve(5)->getStatus());
	}

	public function testTheWaitingAdministratorsAreListedForTheViewerOldestFirst(): void {
		$service = $this->createMock(ApprovalService::class);
		$service->expects($this->once())->method('list')->with(true, 200, Approval::KIND_ADMIN_GRANT)->willReturn([
			$this->grant(3, 'dave', 'carol', self::NOW + 60),
			$this->grant(2, 'bob', 'alice', self::NOW + 60),
			$this->grant(1, 'erin', 'alice', self::NOW),
		]);
		$list = $this->controller($service)->adminGrants()->getData();
		$this->assertSame([2, 3], array_column($list, 'id'), 'Oldest first, the expired one left out');
		$this->assertSame(['uid' => 'bob', 'displayName' => 'Bob Builder', 'group' => 'admin', 'requestedBy' => 'alice', 'requesterName' => 'Alice Liddell', 'canApprove' => true], array_intersect_key($list[0], array_flip(['uid', 'displayName', 'group', 'requestedBy', 'requesterName', 'canApprove'])));
		$this->assertFalse($list[1]['canApprove'], 'The one who asked cannot approve');
		$this->assertSame('dave', $list[1]['displayName']);
	}

	public function testTheListCanBeLimitedToOneKind(): void {
		$service = $this->createMock(ApprovalService::class);
		$service->expects($this->exactly(2))->method('list')
			->willReturnCallback(function (bool $pendingOnly, int $limit, ?string $kind): array {
				$this->assertContains($kind, [Approval::KIND_LOGIN, null]);
				return [];
			});
		$this->controller($service)->index(kind: 'login');
		$this->controller($service)->index(kind: 'anything else');
	}

	/**
	 * @return array<string, array{string, int}>
	 */
	public static function refusals(): array {
		return [
			'unknown' => [ApprovalException::NOT_FOUND, Http::STATUS_NOT_FOUND],
			'the one who asked' => [ApprovalException::REQUESTER, Http::STATUS_FORBIDDEN],
			'the account itself' => [ApprovalException::SUBJECT, Http::STATUS_FORBIDDEN],
			'expired' => [ApprovalException::EXPIRED, Http::STATUS_BAD_REQUEST],
			'decided' => [ApprovalException::NOT_PENDING, Http::STATUS_BAD_REQUEST],
		];
	}

	#[DataProvider('refusals')]
	public function testRefusalsBecomeErrors(string $reason, int $status): void {
		$service = $this->createMock(ApprovalService::class);
		$service->method('reject')->willThrowException(new ApprovalException($reason));
		$response = $this->answer(fn () => $this->controller($service)->reject(5));
		$this->assertSame($status, $response->getStatus());
		$this->assertSame($reason, $response->getData()['reason']);
	}

	private function grant(int $id, string $subject, string $requester, int $expiresAt): Approval {
		$approval = new Approval();
		$approval->setId($id);
		$approval->setKind(Approval::KIND_ADMIN_GRANT);
		$approval->setSubjectUid($subject);
		$approval->setRequestedBy($requester);
		$approval->setGroupId('admin');
		$approval->setStatus(Approval::STATUS_PENDING);
		$approval->setCreatedAt(self::NOW - 100 + $id);
		$approval->setExpiresAt($expiresAt);
		return $approval;
	}

	private function userSession(): IUserSession {
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn('carol');
		$user->method('getBackendClassName')->willReturn('Database');
		$session = $this->createMock(IUserSession::class);
		$session->method('getUser')->willReturn($user);
		return $session;
	}

	private function controller(ApprovalService $service): ApprovalController {
		$session = $this->userSession();
		$l = $this->createMock(IL10N::class);
		$l->method('t')->willReturnArgument(0);
		$state = $this->createMock(SessionState::class);
		$state->method('get')->willReturnCallback(fn (string $name): ?array => match ($name) {
			SessionState::CONFIRMATION => $this->confirmation,
			SessionState::STEP_UP => $this->stepUp,
			default => null,
		});
		$phpSession = $this->createMock(ISession::class);
		$phpSession->method('exists')->willReturnCallback(fn (string $key): bool => $key === 'app_password' && $this->appPassword);
		$confirmation = new SessionConfirmation($state, new CoreSession($phpSession, $this->createMock(\OCP\Authentication\Token\IProvider::class), $this->createMock(LoggerInterface::class)), $this->createMock(ITimeFactory::class));
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturn(self::NOW);
		return new ApprovalController($this->createMock(IRequest::class), $l, new ActorResolver($session), $session, $service, $confirmation, $this->userManager, $time);
	}
}
