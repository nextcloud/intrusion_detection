<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Controller;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\InvalidParamException;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\OCSController;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IUserSession;

/**
 * Shared parts of the admin page's controllers: who is acting, and errors
 * the page can show next to the field they are about.
 *
 * Subclasses are for administrators only: they carry no attribute that
 * relaxes core's default admin requirement.
 *
 * @psalm-import-type IntrusionDetectionError from ResponseDefinitions
 */
abstract class AdminOCSController extends OCSController {
	public function __construct(
		IRequest $request,
		protected readonly IL10N $l,
		protected readonly IUserSession $userSession,
	) {
		parent::__construct(Application::APP_ID, $request);
	}

	protected function actor(): string {
		return $this->userSession->getUser()?->getUID() ?? 'unknown';
	}

	/**
	 * @return DataResponse<Http::STATUS_BAD_REQUEST, IntrusionDetectionError, array{}>
	 */
	protected function invalid(InvalidParamException $e): DataResponse {
		$param = $e->details['param'] ?? null;
		return $this->error($e->describe($this->l), $param === null ? null : (string)$param, $e->reason);
	}

	/**
	 * @return DataResponse<Http::STATUS_BAD_REQUEST, IntrusionDetectionError, array{}>
	 */
	protected function error(string $message, ?string $param, string $reason): DataResponse {
		return new DataResponse(['message' => $message, 'param' => $param, 'reason' => $reason], Http::STATUS_BAD_REQUEST);
	}
}
