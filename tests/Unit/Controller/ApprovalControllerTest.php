<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Controller;

use OCA\IntrusionDetection\AdminChange\ApprovalException;
use OCA\IntrusionDetection\AdminChange\ApprovalService;
use OCA\IntrusionDetection\Controller\ApprovalController;
use OCA\IntrusionDetection\Db\Approval;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\NoAdminRequired;
use OCP\AppFramework\Http\Attribute\NoCSRFRequired;
use OCP\AppFramework\Http\Attribute\PasswordConfirmationRequired;
use OCP\AppFramework\Http\Attribute\PublicPage;
use OCP\AppFramework\Http\Attribute\UserRateLimit;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IUser;
use OCP\IUserSession;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class ApprovalControllerTest extends TestCase {
	/** @var ?array<string, mixed> how the deciding administrator's own login was confirmed */
	private ?array $confirmation = null;

	/**
	 * @return array<string, array{string}>
	 */
	public static function decisions(): array {
		return ['approve' => ['approve'], 'reject' => ['reject']];
	}

	#[DataProvider('decisions')]
	public function testDecisionsNeedPasswordConfirmationAndAreRateLimited(string $method): void {
		$reflection = new \ReflectionMethod(ApprovalController::class, $method);
		$this->assertCount(1, $reflection->getAttributes(PasswordConfirmationRequired::class));
		$this->assertCount(1, $reflection->getAttributes(UserRateLimit::class));
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
		$response = $this->controller($service)->approve(5);
		$this->assertSame(Http::STATUS_OK, $response->getStatus());
		$this->assertSame(Approval::STATUS_APPROVED, $response->getData()['status']);
	}

	public function testAnAdministratorWhoseOwnLoginWasNotConfirmedCannotApprove(): void {
		$service = $this->createMock(ApprovalService::class);
		$service->expects($this->never())->method('approve');
		$this->confirmation = ['uid' => 'carol', 'by' => 'none', 'policies' => ['flagged_source'], 'at' => 1];
		$response = $this->controller($service)->approve(5);
		$this->assertSame(Http::STATUS_FORBIDDEN, $response->getStatus());
		$this->assertSame(ApprovalException::UNCONFIRMED, $response->getData()['reason']);

		$this->confirmation = ['uid' => 'carol', 'by' => 'email_code', 'policies' => ['flagged_source'], 'at' => 1];
		$approval = new Approval();
		$approval->setStatus(Approval::STATUS_APPROVED);
		$other = $this->createMock(ApprovalService::class);
		$other->expects($this->once())->method('approve')->willReturn($approval);
		$this->assertSame(Http::STATUS_OK, $this->controller($other)->approve(5)->getStatus());
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
		$response = $this->controller($service)->reject(5);
		$this->assertSame($status, $response->getStatus());
		$this->assertSame($reason, $response->getData()['reason']);
	}

	private function controller(ApprovalService $service): ApprovalController {
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn('carol');
		$session = $this->createMock(IUserSession::class);
		$session->method('getUser')->willReturn($user);
		$l = $this->createMock(IL10N::class);
		$l->method('t')->willReturnArgument(0);
		$state = $this->createMock(SessionState::class);
		$state->method('get')->willReturnCallback(fn (string $name): ?array => $name === SessionState::CONFIRMATION ? $this->confirmation : null);
		return new ApprovalController($this->createMock(IRequest::class), $service, $session, $l, $state);
	}
}
