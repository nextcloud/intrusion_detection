<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Controller;

use OCA\IntrusionDetection\AdminChange\ActorResolver;
use OCA\IntrusionDetection\AdminChange\ApprovalException;
use OCA\IntrusionDetection\AdminChange\ApprovalService;
use OCA\IntrusionDetection\Check\Checks\AdminChange\AdminChange;
use OCA\IntrusionDetection\Confirm\SessionConfirmation;
use OCA\IntrusionDetection\Db\Approval;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\ApiRoute;
use OCP\AppFramework\Http\Attribute\OpenAPI;
use OCP\AppFramework\Http\Attribute\PasswordConfirmationRequired;
use OCP\AppFramework\Http\Attribute\UserRateLimit;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IUserManager;
use OCP\IUserSession;

/**
 * Requests for the approval of a second administrator: the list, and the
 * decisions, made on the admin page or by API.
 *
 * Administrators only (the default for controllers) and CSRF-protected; the
 * rules who may decide are in {@see ApprovalService}, shared with occ.
 *
 * Approving needs a recent password confirmation, and the deciding
 * administrator's own session must not be unconfirmed
 * ({@see SessionConfirmation::isUnconfirmed()}): a session that was let in
 * without its confirmation, still waits for it, or uses an app password
 * must not let others in. So a stolen app password alone never approves.
 *
 * Rejecting needs neither: it changes nothing (the account does not join,
 * the waiting login ends and can be tried again), and stopping a request
 * one did not expect must be quick.
 *
 * @psalm-import-type IntrusionDetectionApproval from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionAdminGrantRequest from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionError from ResponseDefinitions
 */
#[OpenAPI(scope: OpenAPI::SCOPE_ADMINISTRATION)]
class ApprovalController extends AdminOCSController {
	public function __construct(
		IRequest $request,
		IL10N $l,
		ActorResolver $actors,
		private readonly IUserSession $userSession,
		private readonly ApprovalService $approvals,
		private readonly SessionConfirmation $confirmation,
		private readonly IUserManager $userManager,
		private readonly ITimeFactory $timeFactory,
		private readonly AdminChange $adminChange,
	) {
		parent::__construct($request, $l, $actors);
	}

	/**
	 * List requests for approval
	 *
	 * @param bool $all also the decided ones of the last 90 days
	 * @param int<1, 200> $limit the most requests to return
	 * @param ?string $kind only requests of this kind: admin_grant, settings or login
	 * @return DataResponse<Http::STATUS_OK, list<IntrusionDetectionApproval>, array{}>
	 *
	 * 200: The requests, newest first
	 */
	#[ApiRoute(verb: 'GET', url: '/api/v1/approvals')]
	public function index(bool $all = false, int $limit = 200, ?string $kind = null): DataResponse {
		$kind = in_array($kind, [Approval::KIND_ADMIN_GRANT, Approval::KIND_SETTINGS, Approval::KIND_LOGIN], true) ? $kind : null;
		/** @var list<IntrusionDetectionApproval> $list */
		$list = array_map(static fn (Approval $a): array => $a->jsonSerialize(), $this->approvals->list(!$all, max(1, min(200, $limit)), $kind));
		return new DataResponse($list);
	}

	/**
	 * List the accounts waiting to become administrators, and the changes waiting to switch that approval off
	 *
	 * The pending requests that have not expired, for the admin page. A
	 * settings change is about the administrator who asked; `change` says
	 * what it does.
	 *
	 * @return DataResponse<Http::STATUS_OK, list<IntrusionDetectionAdminGrantRequest>, array{}>
	 *
	 * 200: The requests, oldest first
	 */
	#[ApiRoute(verb: 'GET', url: '/api/v1/approvals/admin-grants')]
	public function adminGrants(): DataResponse {
		$viewer = $this->userSession->getUser()?->getUID() ?? '';
		$now = $this->timeFactory->getTime();
		$requests = array_merge($this->approvals->list(true, 200, Approval::KIND_ADMIN_GRANT), $this->approvals->list(true, 200, Approval::KIND_SETTINGS));
		usort($requests, static fn (Approval $a, Approval $b): int => [$a->getCreatedAt(), (int)$a->getId()] <=> [$b->getCreatedAt(), (int)$b->getId()]);
		$list = [];
		foreach ($requests as $approval) {
			if ($approval->getExpiresAt() <= $now) {
				continue;
			}
			$uid = $approval->getSubjectUid();
			$requester = $approval->getRequestedBy();
			$settings = $approval->getKind() === Approval::KIND_SETTINGS;
			$list[] = [
				'id' => (int)$approval->getId(),
				'kind' => $settings ? Approval::KIND_SETTINGS : Approval::KIND_ADMIN_GRANT,
				'change' => $settings ? $this->adminChange->heldChange($approval->heldChange(), $this->l) : null,
				'uid' => $uid,
				'displayName' => $this->userManager->getDisplayName($uid) ?? $uid,
				'group' => (string)$approval->getGroupId(),
				'requestedBy' => $requester,
				'requesterName' => ActorResolver::isPerson($requester) ? ($this->userManager->getDisplayName($requester) ?? $requester) : AdminChange::actorName($requester, $this->l),
				'createdAt' => $approval->getCreatedAt(),
				'expiresAt' => $approval->getExpiresAt(),
				'canApprove' => $viewer !== $uid && $viewer !== $requester,
			];
		}
		return new DataResponse($list);
	}

	/**
	 * Approve a request: the account joins the group, the change is made, or the waiting login continues
	 *
	 * Needs a recent password confirmation, which apps and clients cannot
	 * give: their notification opens the admin page instead.
	 *
	 * @param int $id the request
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionApproval, array{}>|DataResponse<Http::STATUS_BAD_REQUEST|Http::STATUS_FORBIDDEN|Http::STATUS_NOT_FOUND, IntrusionDetectionError, array{}>
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
		$decider = $this->decider();
		if ($this->confirmation->isUnconfirmed($decider)) {
			throw new ApprovalException(ApprovalException::UNCONFIRMED);
		}
		return new DataResponse($this->approvals->approve($id, $decider, ApprovalService::VIA_WEB)->jsonSerialize());
	}

	/**
	 * Reject a request: nothing changes, and the one who asked is told
	 *
	 * @param int $id the request
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionApproval, array{}>|DataResponse<Http::STATUS_BAD_REQUEST|Http::STATUS_FORBIDDEN|Http::STATUS_NOT_FOUND, IntrusionDetectionError, array{}>
	 *
	 * 200: Rejected
	 * 400: The request was already decided or has expired
	 * 403: This administrator may not decide on it
	 * 404: There is no such request
	 */
	#[ApiRoute(verb: 'POST', url: '/api/v1/approvals/{id}/reject', requirements: ['id' => '\d+'])]
	#[UserRateLimit(limit: 10, period: 60)]
	public function reject(int $id): DataResponse {
		return new DataResponse($this->approvals->reject($id, $this->decider(), ApprovalService::VIA_WEB)->jsonSerialize());
	}

	private function decider(): string {
		// The admin middleware already required a logged-in administrator.
		return $this->userSession->getUser()?->getUID() ?? throw new ApprovalException(ApprovalException::NOT_ADMIN);
	}

}
