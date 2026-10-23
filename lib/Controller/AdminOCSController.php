<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Controller;

use OCA\IntrusionDetection\AdminChange\ActorResolver;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Middleware\ApiErrorMiddleware;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\OCS\OCSNotFoundException;
use OCP\AppFramework\OCSController;
use OCP\IL10N;
use OCP\IRequest;

/**
 * Shared parts of the admin page's controllers: who is acting, and errors
 * the page can show next to the field they are about. Domain errors that
 * a controller does not catch are answered by {@see ApiErrorMiddleware}
 * in the same shape.
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
		private readonly ActorResolver $actors,
	) {
		parent::__construct(Application::APP_ID, $request);
	}

	protected function actor(): string {
		return $this->actors->user();
	}

	/**
	 * What a lookup finds, or "not found" with this message when it finds nothing.
	 *
	 * @template T
	 * @param \Closure(): T $lookup
	 * @return T
	 * @throws OCSNotFoundException
	 */
	protected function found(\Closure $lookup, string $message): mixed {
		try {
			return $lookup();
		} catch (DoesNotExistException) {
			throw new OCSNotFoundException($message);
		}
	}

	/**
	 * @return DataResponse<Http::STATUS_BAD_REQUEST, IntrusionDetectionError, array{}>
	 */
	protected function error(string $message, ?string $param, string $reason): DataResponse {
		return new DataResponse(['message' => $message, 'param' => $param, 'reason' => $reason], Http::STATUS_BAD_REQUEST);
	}
}
