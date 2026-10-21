<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Controller;

use OCA\IntrusionDetection\AppInfo\Application;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\Attribute\FrontpageRoute;
use OCP\AppFramework\Http\Attribute\NoAdminRequired;
use OCP\AppFramework\Http\Attribute\NoCSRFRequired;
use OCP\AppFramework\Http\Attribute\OpenAPI;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\IRequest;
use OCP\Util;

/**
 * The "Secure my account" page (concept section 15.3). It only loads the
 * page; the checklist reads and writes through the personal OCS API, for
 * the logged-in user's own account.
 */
#[OpenAPI(scope: OpenAPI::SCOPE_IGNORE)]
class SecureAccountController extends Controller {
	public function __construct(
		IRequest $request,
	) {
		parent::__construct(Application::APP_ID, $request);
	}

	#[NoAdminRequired]
	#[NoCSRFRequired]
	#[FrontpageRoute(verb: 'GET', url: '/secure-account')]
	public function page(): TemplateResponse {
		Util::addStyle(Application::APP_ID, 'secure-account');
		Util::addScript(Application::APP_ID, 'secure-account');
		return new TemplateResponse(Application::APP_ID, 'secure-account');
	}
}
