<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Controller;

use OCA\IntrusionDetection\Admin\PrivacyOverview;
use OCA\IntrusionDetection\Blocklist\ContributionOverview;
use OCA\IntrusionDetection\Blocklist\ContributionSettings;
use OCA\IntrusionDetection\Check\InvalidParamException;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\ApiRoute;
use OCP\AppFramework\Http\Attribute\OpenAPI;
use OCP\AppFramework\Http\Attribute\PasswordConfirmationRequired;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\OCS\OCSNotFoundException;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IUserSession;

/**
 * The "Data and privacy" tab. Administrators only; changes need a recent
 * password confirmation and are audited.
 *
 * @psalm-import-type IntrusionDetectionPrivacy from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionContribution from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionError from ResponseDefinitions
 */
#[OpenAPI(scope: OpenAPI::SCOPE_ADMINISTRATION)]
class PrivacyApiController extends AdminOCSController {
	public function __construct(
		IRequest $request,
		IL10N $l,
		IUserSession $userSession,
		private readonly PrivacyOverview $overview,
		private readonly ContributionSettings $contribution,
		private readonly ContributionOverview $contributionOverview,
	) {
		parent::__construct($request, $l, $userSession);
	}

	/**
	 * What is stored, and what leaves the server
	 *
	 * Every kind of data the checks store, with why and for how long; the
	 * data sent to other services; and, where it is available, the shared
	 * blocklist contribution with a preview of the exact next report.
	 *
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionPrivacy, array{}>
	 *
	 * 200: Overview returned
	 */
	#[ApiRoute(verb: 'GET', url: '/api/v1/privacy')]
	public function index(): DataResponse {
		return new DataResponse($this->overview->get($this->l));
	}

	/**
	 * Change the shared blocklist contribution
	 *
	 * Only available while config.php has intrusion_detection.contribution_available.
	 *
	 * @param bool|null $enabled Send reports once a day
	 * @param string|null $url Where to send them: an https:// address outside the local network; empty to remove it
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionContribution, array{}>|DataResponse<Http::STATUS_BAD_REQUEST, IntrusionDetectionError, array{}>
	 * @throws OCSNotFoundException The contribution is not available on this server
	 *
	 * 200: Contribution changed
	 * 400: The address is refused
	 */
	#[ApiRoute(verb: 'PUT', url: '/api/v1/contribution')]
	#[PasswordConfirmationRequired]
	public function updateContribution(?bool $enabled = null, ?string $url = null): DataResponse {
		if (!$this->contribution->isAvailable()) {
			throw new OCSNotFoundException($this->l->t('Contributing to a shared blocklist is not available on this server.'));
		}
		try {
			if ($url !== null) {
				$this->contribution->setUrl($url, $this->actor());
			}
			if ($enabled !== null) {
				$this->contribution->setEnabled($enabled, $this->actor());
			}
		} catch (InvalidParamException $e) {
			return $this->error($e->describe($this->l), 'url', $e->reason);
		}
		$view = $this->contributionOverview->get($this->l)
			?? throw new OCSNotFoundException($this->l->t('Contributing to a shared blocklist is not available on this server.'));
		return new DataResponse($view);
	}
}
