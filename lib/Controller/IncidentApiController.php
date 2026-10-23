<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Controller;

use OCA\IntrusionDetection\Incident\IncidentQuery;
use OCA\IntrusionDetection\Incident\IncidentReports;
use OCA\IntrusionDetection\Incident\InvalidIncidentQuery;
use OCA\IntrusionDetection\Incident\ReportFormat;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\ApiRoute;
use OCP\AppFramework\Http\Attribute\OpenAPI;
use OCP\AppFramework\Http\Attribute\PasswordConfirmationRequired;
use OCP\AppFramework\Http\Attribute\UserRateLimit;
use OCP\AppFramework\Http\DataDownloadResponse;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IUserSession;

/**
 * The incident report on the Incidents tab.
 * Administrators only.
 *
 * A report reveals what Nextcloud knows about an account or an address, so
 * every way to get one needs a recent password confirmation, is rate
 * limited and written to the audit log. Downloads are POST requests that
 * answer with the document itself: the page fetches it with its CSRF token
 * and password confirmation, then saves or prints it. No link, ticket or
 * copy of the report exists on the server afterwards.
 *
 * @psalm-import-type IntrusionDetectionIncidentReport from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionError from ResponseDefinitions
 */
#[OpenAPI(scope: OpenAPI::SCOPE_ADMINISTRATION)]
class IncidentApiController extends AdminOCSController {
	public function __construct(
		IRequest $request,
		IL10N $l,
		IUserSession $userSession,
		private readonly IncidentReports $reports,
		private readonly ITimeFactory $timeFactory,
	) {
		parent::__construct($request, $l, $userSession);
	}

	/**
	 * Build an incident report to show on the page
	 *
	 * One timeline for an account or an address over a period (at most 90
	 * days; by default the 7 days before now), with a summary on top.
	 *
	 * @param string $user The account, or empty when the report is about an address
	 * @param string $address The address, or empty when the report is about an account
	 * @param int|null $since Start of the period, Unix time
	 * @param int|null $until End of the period, Unix time
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionIncidentReport, array{}>|DataResponse<Http::STATUS_BAD_REQUEST, IntrusionDetectionError, array{}>
	 *
	 * 200: Report built
	 * 400: The account, the address or the period is not valid
	 */
	#[ApiRoute(verb: 'POST', url: '/api/v1/incidents/report')]
	#[PasswordConfirmationRequired]
	#[UserRateLimit(limit: 30, period: 600)]
	public function report(string $user = '', string $address = '', ?int $since = null, ?int $until = null): DataResponse {
		$query = $this->query($user, $address, $since, $until);
		$response = new DataResponse($this->reports->report($query, $this->actor(), $this->l)->toArray());
		$response->addHeader('Cache-Control', 'no-store');
		return $response;
	}

	/**
	 * Download an incident report
	 *
	 * The same report as a file: JSON with a schema version, or an HTML page
	 * to print or save as PDF. The answer is the document itself.
	 *
	 * @param 'json'|'html' $output The kind of document; not called "format", which chooses the OCS response format
	 * @param string $user The account, or empty when the report is about an address
	 * @param string $address The address, or empty when the report is about an account
	 * @param int|null $since Start of the period, Unix time
	 * @param int|null $until End of the period, Unix time
	 * @return DataDownloadResponse<Http::STATUS_OK, 'application/json; charset=utf-8'|'text/html; charset=utf-8', array{}>|DataResponse<Http::STATUS_BAD_REQUEST, IntrusionDetectionError, array{}>
	 *
	 * 200: The document
	 * 400: The kind of document, the account, the address or the period is not valid
	 */
	#[ApiRoute(verb: 'POST', url: '/api/v1/incidents/report/download')]
	#[PasswordConfirmationRequired]
	#[UserRateLimit(limit: 30, period: 600)]
	public function download(string $output, string $user = '', string $address = '', ?int $since = null, ?int $until = null): DataDownloadResponse|DataResponse {
		$format = match ($output) {
			'json' => ReportFormat::Json,
			'html' => ReportFormat::Html,
			default => null,
		};
		if ($format === null) {
			return $this->error($this->l->t('Choose JSON or HTML.'), 'output', 'invalid_output');
		}
		$query = $this->query($user, $address, $since, $until);
		$document = $this->reports->document($query, $format, $this->actor(), $this->l);
		/** @var 'application/json; charset=utf-8'|'text/html; charset=utf-8' $contentType */
		$contentType = $document['contentType'];
		$response = new DataDownloadResponse($document['body'], $document['filename'], $contentType);
		$response->addHeader('Cache-Control', 'no-store');
		$response->addHeader('X-Content-Type-Options', 'nosniff');
		return $response;
	}

	/**
	 * @throws InvalidIncidentQuery
	 */
	private function query(string $user, string $address, ?int $since, ?int $until): IncidentQuery {
		$user = trim($user);
		$address = trim($address);
		if (($user === '') === ($address === '')) {
			throw new InvalidIncidentQuery(InvalidIncidentQuery::SUBJECT);
		}
		$now = $this->timeFactory->getTime();
		return $user !== ''
			? IncidentQuery::forUser($user, $since, $until, $now)
			: IncidentQuery::forAddress($address, $since, $until, $now);
	}
}
