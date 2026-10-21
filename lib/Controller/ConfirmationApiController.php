<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Controller;

use OCA\IntrusionDetection\Admin\ConfirmationOverview;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\InvalidParamException;
use OCA\IntrusionDetection\Confirm\ConfirmationCoverage;
use OCA\IntrusionDetection\Confirm\NoMethodPreset;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\ApiRoute;
use OCP\AppFramework\Http\Attribute\OpenAPI;
use OCP\AppFramework\Http\Attribute\PasswordConfirmationRequired;
use OCP\AppFramework\Http\DataResponse;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IUserSession;

/**
 * Login confirmation on the admin page. Its settings are changed through
 * the settings endpoint or, for the outcomes of all reasons at once, the
 * preset endpoint; waiting logins are decided through the approvals
 * endpoints. Every change needs password confirmation. Administrators only.
 *
 * @psalm-import-type IntrusionDetectionConfirmation from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionConfirmationPreset from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionError from ResponseDefinitions
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
		private readonly NoMethodPreset $preset,
		private readonly AuditLogger $audit,
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

	/**
	 * Decide what happens to every login that cannot be confirmed
	 *
	 * Sets the outcome of every reason at once: "recommended" (the default of
	 * each reason), "refuse", or "allow" (let it in and tell the user and the
	 * administrators; with a leaked password a new one is required).
	 *
	 * @param string $preset recommended, refuse or allow
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionConfirmationPreset, array{}>|DataResponse<Http::STATUS_BAD_REQUEST, IntrusionDetectionError, array{}>
	 *
	 * 200: Outcomes set
	 * 400: Unknown preset; nothing was saved
	 */
	#[ApiRoute(verb: 'PUT', url: '/api/v1/confirmation/preset')]
	#[PasswordConfirmationRequired]
	public function setPreset(string $preset): DataResponse {
		try {
			$changes = $this->preset->apply($preset);
		} catch (InvalidParamException $e) {
			return $this->invalid($e);
		}
		if ($changes !== []) {
			$this->audit->log('login confirmation without a method set to %s by %s: %s', [
				'preset' => $preset,
				'actor' => $this->actor(),
				'change' => json_encode($changes),
			]);
		}
		return new DataResponse(['preset' => $this->preset->current(), 'policies' => $this->overview->policies($this->l)]);
	}
}
