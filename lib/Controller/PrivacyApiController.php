<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Controller;

use OCA\IntrusionDetection\Admin\PrivacyOverview;
use OCA\IntrusionDetection\AdminChange\ActorResolver;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\ApiRoute;
use OCP\AppFramework\Http\Attribute\OpenAPI;
use OCP\AppFramework\Http\DataResponse;
use OCP\IL10N;
use OCP\IRequest;

/**
 * The "Data and privacy" tab. Administrators only.
 *
 * @psalm-import-type IntrusionDetectionPrivacy from ResponseDefinitions
 */
#[OpenAPI(scope: OpenAPI::SCOPE_ADMINISTRATION)]
class PrivacyApiController extends AdminOCSController {
	public function __construct(
		IRequest $request,
		IL10N $l,
		ActorResolver $actors,
		private readonly PrivacyOverview $overview,
	) {
		parent::__construct($request, $l, $actors);
	}

	/**
	 * What is stored, and what leaves the server
	 *
	 * Every kind of data the checks store, with why and for how long, and the
	 * data sent to other services.
	 *
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionPrivacy, array{}>
	 *
	 * 200: Overview returned
	 */
	#[ApiRoute(verb: 'GET', url: '/api/v1/privacy')]
	public function index(): DataResponse {
		return new DataResponse($this->overview->get($this->l));
	}

}
