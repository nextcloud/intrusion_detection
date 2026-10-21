<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Controller;

use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Notification\DigestSender;
use OCA\IntrusionDetection\ResponseDefinitions;
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
 * The admin page's API for the digest email.
 * Administrators only, like the rest of the admin API.
 *
 * @psalm-import-type IntrusionDetectionDigest from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionMessage from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionError from ResponseDefinitions
 */
#[OpenAPI(scope: OpenAPI::SCOPE_ADMINISTRATION)]
class DigestApiController extends OCSController {
	public function __construct(
		string $appName,
		IRequest $request,
		private readonly IL10N $l,
		private readonly IUserSession $userSession,
		private readonly DigestSender $digests,
		private readonly AuditLogger $audit,
	) {
		parent::__construct($appName, $request);
	}

	/**
	 * Show the digest settings and who gets the digest
	 *
	 * Includes the members of the notification groups who have no email
	 * address and therefore get no digest.
	 *
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionDigest, array{}>
	 *
	 * 200: Digest overview returned
	 */
	#[ApiRoute(verb: 'GET', url: '/api/v1/digest')]
	public function digest(): DataResponse {
		return new DataResponse($this->digests->overview($this->userSession->getUser()));
	}

	/**
	 * Send a test digest to yourself
	 *
	 * The digest of the last week (or day, for daily digests) up to now,
	 * marked as a test and sent only to the administrator who asks. It does
	 * not replace the next real digest.
	 *
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionMessage, array{}>|DataResponse<Http::STATUS_BAD_REQUEST, IntrusionDetectionError, array{}>
	 *
	 * 200: Test digest sent
	 * 400: You have no email address, or the email could not be sent
	 */
	#[ApiRoute(verb: 'POST', url: '/api/v1/digest/test')]
	#[PasswordConfirmationRequired]
	#[UserRateLimit(limit: 5, period: 600)]
	public function sendTest(): DataResponse {
		$user = $this->userSession->getUser();
		$result = $user === null ? DigestSender::TEST_NO_ADDRESS : $this->digests->sendTest($user);
		if ($result === DigestSender::TEST_NO_ADDRESS) {
			return new DataResponse([
				'message' => $this->l->t('You have no email address, so the test digest cannot be sent. Add one in your personal settings.'),
				'param' => null,
				'reason' => 'no_address',
			], Http::STATUS_BAD_REQUEST);
		}
		if ($result === DigestSender::TEST_FAILED) {
			return new DataResponse([
				'message' => $this->l->t('The test digest could not be sent. Check the email server settings and the server log.'),
				'param' => null,
				'reason' => 'send_failed',
			], Http::STATUS_BAD_REQUEST);
		}
		$this->audit->log('test digest sent to %s', ['actor' => $user?->getUID() ?? 'unknown']);
		return new DataResponse(['message' => $this->l->t('The test digest was sent to %s.', [(string)$user?->getEMailAddress()])]);
	}
}
