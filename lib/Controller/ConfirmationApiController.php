<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Controller;

use OCA\IntrusionDetection\Admin\ConfirmationOverview;
use OCA\IntrusionDetection\Confirm\ConfirmationCoverage;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\ApiRoute;
use OCP\AppFramework\Http\Attribute\OpenAPI;
use OCP\AppFramework\Http\DataResponse;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IUserSession;

/**
 * The Confirmation tab of the admin page: read-only. Its settings are
 * changed through the settings endpoint, and waiting logins are decided
 * through the approvals endpoints, both with password confirmation.
 * Administrators only.
 *
 * @psalm-import-type IntrusionDetectionConfirmation from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionUnconfirmableAccount from ResponseDefinitions
 */
#[OpenAPI(scope: OpenAPI::SCOPE_ADMINISTRATION)]
class ConfirmationApiController extends AdminOCSController {
	public function __construct(
		IRequest $request,
		IL10N $l,
		IUserSession $userSession,
		private readonly ConfirmationOverview $overview,
		private readonly ConfirmationCoverage $coverage,
	) {
		parent::__construct($request, $l, $userSession);
	}

	/**
	 * How logins are confirmed
	 *
	 * The confirmation methods in the order they are tried, what happens per
	 * reason when nothing can confirm, how many accounts cannot confirm a
	 * login, and the logins that wait for an administrator.
	 *
	 * @param bool $refresh count the accounts again instead of using the counts of the last hour
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionConfirmation, array{}>
	 *
	 * 200: Overview returned
	 */
	#[ApiRoute(verb: 'GET', url: '/api/v1/confirmation')]
	public function index(bool $refresh = false): DataResponse {
		if ($refresh) {
			$this->coverage->refresh();
		}
		return new DataResponse($this->overview->get($this->l, $this->actor()));
	}

	/**
	 * List the active accounts that cannot confirm a login
	 *
	 * Accounts with neither a second factor nor an email address, by account name.
	 *
	 * @param int<1, 200> $limit at most this many
	 * @param int<0, max> $offset skip this many
	 * @param bool $admins only members of the admin group
	 * @return DataResponse<Http::STATUS_OK, list<IntrusionDetectionUnconfirmableAccount>, array{}>
	 *
	 * 200: The accounts
	 */
	#[ApiRoute(verb: 'GET', url: '/api/v1/confirmation/accounts')]
	public function accounts(int $limit = 50, int $offset = 0, bool $admins = false): DataResponse {
		return new DataResponse($this->coverage->list(max(1, min(ConfirmationCoverage::MAX_LIST, $limit)), max(0, $offset), $admins));
	}
}
