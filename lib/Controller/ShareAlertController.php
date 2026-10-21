<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Controller;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Notification\ShareOwnerAlerts;
use OCA\IntrusionDetection\Share\ShareLinks;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\ApiRoute;
use OCP\AppFramework\Http\Attribute\NoAdminRequired;
use OCP\AppFramework\Http\Attribute\OpenAPI;
use OCP\AppFramework\Http\Attribute\UserRateLimit;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\OCSController;
use OCP\IRequest;
use OCP\IUserSession;

/**
 * The "Disable link" action of the notification that tells someone the
 * password of their share is being guessed.
 */
#[OpenAPI(scope: OpenAPI::SCOPE_DEFAULT)]
class ShareAlertController extends OCSController {
	public function __construct(
		IRequest $request,
		private readonly ShareLinks $links,
		private readonly ShareOwnerAlerts $alerts,
		private readonly IUserSession $userSession,
	) {
		parent::__construct(Application::APP_ID, $request);
	}

	/**
	 * Turn off the share link a detection is about. Only someone who manages
	 * the share can do this; for anyone else the detection does not exist.
	 * Turning off a link that is already gone succeeds again.
	 *
	 * @param int $detectionId The detection from the notification
	 * @return DataResponse<Http::STATUS_OK, array{status: 'disabled'|'already_gone'}, array{}>|DataResponse<Http::STATUS_NOT_FOUND, array{status: 'not_found'}, array{}>
	 *
	 * 200: The link is off
	 * 404: No share link of the current user belongs to this detection
	 */
	#[NoAdminRequired]
	#[UserRateLimit(limit: 10, period: 600)]
	#[ApiRoute(verb: 'POST', url: '/api/v1/share-alerts/{detectionId}/disable', requirements: ['detectionId' => '\d{1,18}'])]
	public function disable(int $detectionId): DataResponse {
		$uid = $this->userSession->getUser()?->getUID();
		$result = $uid === null ? ShareLinks::NOT_FOUND : $this->links->disable($detectionId, $uid);
		if ($result === ShareLinks::NOT_FOUND) {
			return new DataResponse(['status' => ShareLinks::NOT_FOUND], Http::STATUS_NOT_FOUND);
		}
		$this->alerts->dismiss($detectionId);
		return new DataResponse(['status' => $result]);
	}
}
