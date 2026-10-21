<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Controller;

use OCA\IntrusionDetection\Admin\NotificationOverview;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Notification\TestAlert;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\ApiRoute;
use OCP\AppFramework\Http\Attribute\OpenAPI;
use OCP\AppFramework\Http\Attribute\PasswordConfirmationRequired;
use OCP\AppFramework\Http\Attribute\UserRateLimit;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\OCS\OCSForbiddenException;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IUserSession;

/**
 * The Notifications tab. Administrators only. The settings themselves are
 * changed through the settings endpoint of the admin API.
 *
 * @psalm-import-type IntrusionDetectionNotifications from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionTestAlert from ResponseDefinitions
 */
#[OpenAPI(scope: OpenAPI::SCOPE_ADMINISTRATION)]
class NotificationApiController extends AdminOCSController {
	public function __construct(
		IRequest $request,
		IL10N $l,
		IUserSession $userSession,
		private readonly NotificationOverview $overview,
		private readonly TestAlert $testAlert,
		private readonly AuditLogger $audit,
	) {
		parent::__construct($request, $l, $userSession);
	}

	/**
	 * Show who is notified, and which checks notify
	 *
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionNotifications, array{}>
	 *
	 * 200: Notifications returned
	 */
	#[ApiRoute(verb: 'GET', url: '/api/v1/notifications')]
	public function index(): DataResponse {
		return new DataResponse($this->overview->get($this->userSession->getUser(), $this->l));
	}

	/**
	 * Send a test alert to me
	 *
	 * A notification in Nextcloud and an email to the administrator who asks,
	 * both marked as a test.
	 *
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionTestAlert, array{}>
	 * @throws OCSForbiddenException Nobody is logged in
	 *
	 * 200: Test alert sent; the result says whether the email went out
	 */
	#[ApiRoute(verb: 'POST', url: '/api/v1/notifications/test')]
	#[PasswordConfirmationRequired]
	#[UserRateLimit(limit: 5, period: 600)]
	public function test(): DataResponse {
		$user = $this->userSession->getUser() ?? throw new OCSForbiddenException();
		$result = $this->testAlert->send($user);
		$this->audit->log('test alert sent to %s: email %s', ['actor' => $user->getUID(), 'email' => $result['email']]);
		return new DataResponse($result);
	}
}
