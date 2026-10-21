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
		return new ApprovalController($this->createMock(IRequest::class), $service, $session, $l);
	}
}
