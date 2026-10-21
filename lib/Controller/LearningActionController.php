<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Controller;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Learning\LearningService;
use OCA\IntrusionDetection\Notification\LearningNotices;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\ApiRoute;
use OCP\AppFramework\Http\Attribute\OpenAPI;
use OCP\AppFramework\Http\Attribute\PasswordConfirmationRequired;
use OCP\AppFramework\Http\Attribute\UserRateLimit;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\OCSController;
use OCP\IRequest;
use OCP\IUserSession;

/**
 * The actions of the "learning period ends tomorrow" notification.
 *
 * Administrators only (the default for controllers), CSRF-protected, and
 * idempotent: they act only while that notice is pending. A notification
 * action cannot ask for the password, which is why both actions do only what
 * the notice offered and are written to the audit log.
 */
#[OpenAPI(scope: OpenAPI::SCOPE_ADMINISTRATION)]
class LearningActionController extends OCSController {
	public function __construct(
		IRequest $request,
		private readonly LearningNotices $notices,
		private readonly LearningService $learning,
		private readonly IUserSession $userSession,
	) {
		parent::__construct(Application::APP_ID, $request);
	}

	/**
	 * End learning mode now, so that checks set to Protect start acting
	 *
	 * @return DataResponse<Http::STATUS_OK, array{changed: bool, learning: bool, until: int}, array{}>
	 *
	 * 200: Learning mode state after the action
	 */
	#[ApiRoute(verb: 'POST', url: '/api/v1/learning/protect')]
	#[PasswordConfirmationRequired]
	#[UserRateLimit(limit: 10, period: 60)]
	public function protect(): DataResponse {
		$changed = $this->notices->startProtecting($this->actor());
		return $this->state($changed);
	}

	/**
	 * Observe for 7 more days before protecting
	 *
	 * @return DataResponse<Http::STATUS_OK, array{changed: bool, learning: bool, until: int}, array{}>
	 *
	 * 200: Learning mode state after the action
	 */
	#[ApiRoute(verb: 'POST', url: '/api/v1/learning/extend')]
	#[PasswordConfirmationRequired]
	#[UserRateLimit(limit: 10, period: 60)]
	public function extend(): DataResponse {
		$changed = $this->notices->observeLonger($this->actor());
		return $this->state($changed);
	}

	/**
	 * @return DataResponse<Http::STATUS_OK, array{changed: bool, learning: bool, until: int}, array{}>
	 */
	private function state(bool $changed): DataResponse {
		return new DataResponse([
			'changed' => $changed,
			'learning' => $this->learning->isActive(),
			'until' => $this->learning->until(),
		]);
	}

	private function actor(): string {
		return ($this->userSession->getUser()?->getUID() ?? 'unknown') . ' (notification)';
	}
}
