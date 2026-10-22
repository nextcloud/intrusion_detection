<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Controller;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCA\IntrusionDetection\StaleCredential\StaleCredentialNotices;
use OCA\IntrusionDetection\StaleCredential\StaleCredentials;
use OCA\IntrusionDetection\WasThisYou\AnswerException;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\ApiRoute;
use OCP\AppFramework\Http\Attribute\NoAdminRequired;
use OCP\AppFramework\Http\Attribute\OpenAPI;
use OCP\AppFramework\Http\Attribute\PasswordConfirmationRequired;
use OCP\AppFramework\Http\Attribute\UserRateLimit;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\OCS\OCSNotFoundException;
use OCP\AppFramework\OCSController;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IUser;
use OCP\IUserSession;

/**
 * The current user's app passwords and remembered browsers that have not
 * been used for 90 days, on their security page: list them and remove them.
 *
 * Only the user's own credentials are ever listed or removed, and only
 * stale ones: any other id answers 404, like a missing one. Removing needs
 * a recent password confirmation and is rate limited per user.
 *
 * @psalm-import-type IntrusionDetectionStaleCredential from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionAnswerError from ResponseDefinitions
 */
#[OpenAPI(scope: OpenAPI::SCOPE_DEFAULT)]
class StaleCredentialsApiController extends OCSController {
	public function __construct(
		IRequest $request,
		private readonly IUserSession $userSession,
		private readonly StaleCredentials $credentials,
		private readonly StaleCredentialNotices $notices,
		private readonly AppSettings $settings,
		private readonly IL10N $l,
	) {
		parent::__construct(Application::APP_ID, $request);
	}

	/**
	 * List the current user's app passwords and remembered browsers that have not been used for 90 days
	 *
	 * @param int<1, 200> $limit the most credentials to return
	 * @return DataResponse<Http::STATUS_OK, list<IntrusionDetectionStaleCredential>, array{}>
	 * @throws OCSNotFoundException The security page is switched off
	 *
	 * 200: The credentials, longest unused first; never their secrets
	 */
	#[NoAdminRequired]
	#[ApiRoute(verb: 'GET', url: '/api/v1/personal/stale-credentials')]
	public function index(int $limit = 200): DataResponse {
		$this->requirePage();
		return new DataResponse(array_slice($this->credentials->forUser($this->user()->getUID(), $this->l), 0, max(1, min(200, $limit))));
	}

	/**
	 * Remove one of the current user's app passwords or remembered browsers that have not been used for 90 days
	 *
	 * @param int $id the credential
	 * @return DataResponse<Http::STATUS_OK, array{removed: int}, array{}>|DataResponse<Http::STATUS_NOT_FOUND, IntrusionDetectionAnswerError, array{}>
	 * @throws OCSNotFoundException The security page is switched off
	 *
	 * 200: Removed
	 * 404: The current user has no such unused credential
	 */
	#[NoAdminRequired]
	#[PasswordConfirmationRequired]
	#[UserRateLimit(limit: 30, period: 600)]
	#[ApiRoute(verb: 'DELETE', url: '/api/v1/personal/stale-credentials/{id}', requirements: ['id' => '\d+'])]
	public function destroy(int $id): DataResponse {
		$this->requirePage();
		$uid = $this->user()->getUID();
		if ($this->credentials->remove($uid, $id) === null) {
			return new DataResponse(['reason' => AnswerException::NOT_FOUND, 'message' => $this->l->t('This is not one of your unused app passwords or devices.')], Http::STATUS_NOT_FOUND);
		}
		if ($this->credentials->forUser($uid, $this->l) === []) {
			$this->notices->dismiss($uid);
		}
		return new DataResponse(['removed' => $id]);
	}

	/**
	 * Remove all of the current user's app passwords and remembered browsers that have not been used for 90 days
	 *
	 * @return DataResponse<Http::STATUS_OK, array{removed: int}, array{}>
	 * @throws OCSNotFoundException The security page is switched off
	 *
	 * 200: Removed; `removed` is how many
	 */
	#[NoAdminRequired]
	#[PasswordConfirmationRequired]
	#[UserRateLimit(limit: 10, period: 600)]
	#[ApiRoute(verb: 'DELETE', url: '/api/v1/personal/stale-credentials')]
	public function destroyAll(): DataResponse {
		$this->requirePage();
		$uid = $this->user()->getUID();
		$removed = $this->credentials->removeUnusedSince($uid, $this->credentials->cutoff(), $uid);
		$this->notices->dismiss($uid);
		return new DataResponse(['removed' => count($removed)]);
	}

	/**
	 * @throws OCSNotFoundException
	 */
	private function requirePage(): void {
		if (!$this->settings->personalPageEnabled()) {
			throw new OCSNotFoundException();
		}
	}

	private function user(): IUser {
		$user = $this->userSession->getUser();
		if ($user === null) {
			// The AppFramework lets only logged-in users reach these endpoints.
			throw new \LogicException('Not logged in');
		}
		return $user;
	}
}
