<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Controller;

use OCA\IntrusionDetection\AdminChange\ApprovalException;
use OCA\IntrusionDetection\AdminChange\ApprovalService;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Confirm\StepUpService;
use OCA\IntrusionDetection\Db\Approval;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCA\IntrusionDetection\SessionState\SessionState;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\ApiRoute;
use OCP\AppFramework\Http\Attribute\OpenAPI;
use OCP\AppFramework\Http\Attribute\PasswordConfirmationRequired;
use OCP\AppFramework\Http\Attribute\UserRateLimit;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\OCSController;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IUserSession;

/**
 * Requests for the approval of a second administrator: the list, and the
 * decisions (also the actions of the approval notification).
 *
 * Administrators only (the default for controllers) and CSRF-protected. A
 * decision needs a recent password confirmation; the rules who may decide
 * are in {@see ApprovalService}, shared with occ. Approving also needs the
 * deciding administrator's own login to have been confirmed when it needed
 * a confirmation: a session that was let in without one must not let
 * others in.
 *
 * @psalm-import-type IntrusionDetectionApproval from ResponseDefinitions
 */
#[OpenAPI(scope: OpenAPI::SCOPE_ADMINISTRATION)]
class ApprovalController extends OCSController {
	public function __construct(
		IRequest $request,
		private readonly ApprovalService $approvals,
		private readonly IUserSession $userSession,
		private readonly IL10N $l,
		private readonly SessionState $state,
	) {
		parent::__construct(Application::APP_ID, $request);
	}

	/**
	 * List requests for approval
	 *
	 * @param bool $all also the decided ones of the last 90 days
	 * @param int<1, 200> $limit the most requests to return
	 * @param ?string $kind only requests of this kind: admin_grant or login
	 * @return DataResponse<Http::STATUS_OK, list<IntrusionDetectionApproval>, array{}>
	 *
	 * 200: The requests, newest first
	 */
	#[ApiRoute(verb: 'GET', url: '/api/v1/approvals')]
	public function index(bool $all = false, int $limit = 200, ?string $kind = null): DataResponse {
		$kind = in_array($kind, [Approval::KIND_ADMIN_GRANT, Approval::KIND_LOGIN], true) ? $kind : null;
		/** @var list<IntrusionDetectionApproval> $list */
		$list = array_map(static fn (Approval $a): array => $a->jsonSerialize(), $this->approvals->list(!$all, max(1, min(200, $limit)), $kind));
		return new DataResponse($list);
	}

	/**
	 * Approve a request: the account joins the group, or the waiting login continues
	 *
	 * @param int $id the request
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionApproval, array{}>|DataResponse<Http::STATUS_BAD_REQUEST|Http::STATUS_FORBIDDEN|Http::STATUS_NOT_FOUND, array{reason: string, message: string}, array{}>
	 *
	 * 200: Approved
	 * 400: The request was already decided or has expired
	 * 403: This administrator may not decide on it
	 * 404: There is no such request
	 */
	#[ApiRoute(verb: 'POST', url: '/api/v1/approvals/{id}/approve', requirements: ['id' => '\d+'])]
	#[PasswordConfirmationRequired]
	#[UserRateLimit(limit: 10, period: 60)]
	public function approve(int $id): DataResponse {
		try {
			if (($this->state->get(SessionState::CONFIRMATION)['by'] ?? null) === StepUpService::CONFIRMED_BY_NONE) {
				throw new ApprovalException(ApprovalException::UNCONFIRMED);
			}
			return new DataResponse($this->approvals->approve($id, $this->decider(), ApprovalService::VIA_WEB)->jsonSerialize());
		} catch (ApprovalException $e) {
			return $this->refused($e);
		}
	}

	/**
	 * Reject a request: nothing changes, and the one who asked is told
	 *
	 * @param int $id the request
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionApproval, array{}>|DataResponse<Http::STATUS_BAD_REQUEST|Http::STATUS_FORBIDDEN|Http::STATUS_NOT_FOUND, array{reason: string, message: string}, array{}>
	 *
	 * 200: Rejected
	 * 400: The request was already decided or has expired
	 * 403: This administrator may not decide on it
	 * 404: There is no such request
	 */
	#[ApiRoute(verb: 'POST', url: '/api/v1/approvals/{id}/reject', requirements: ['id' => '\d+'])]
	#[PasswordConfirmationRequired]
	#[UserRateLimit(limit: 10, period: 60)]
	public function reject(int $id): DataResponse {
		try {
			return new DataResponse($this->approvals->reject($id, $this->decider(), ApprovalService::VIA_WEB)->jsonSerialize());
		} catch (ApprovalException $e) {
			return $this->refused($e);
		}
	}

	private function decider(): string {
		// The admin middleware already required a logged-in administrator.
		return $this->userSession->getUser()?->getUID() ?? throw new ApprovalException(ApprovalException::NOT_ADMIN);
	}

	/**
	 * @return DataResponse<Http::STATUS_BAD_REQUEST|Http::STATUS_FORBIDDEN|Http::STATUS_NOT_FOUND, array{reason: string, message: string}, array{}>
	 */
	private function refused(ApprovalException $e): DataResponse {
		$status = match ($e->reason) {
			ApprovalException::NOT_FOUND => Http::STATUS_NOT_FOUND,
			ApprovalException::REQUESTER, ApprovalException::SUBJECT, ApprovalException::NOT_ADMIN, ApprovalException::UNCONFIRMED => Http::STATUS_FORBIDDEN,
			default => Http::STATUS_BAD_REQUEST,
		};
		return new DataResponse(['reason' => $e->reason, 'message' => $e->describe($this->l)], $status);
	}
}
