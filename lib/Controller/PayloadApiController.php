<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Controller;

use OCA\IntrusionDetection\Admin\SignaturePresenter;
use OCA\IntrusionDetection\Check\Payload\CustomSignatures;
use OCA\IntrusionDetection\Check\Payload\PayloadTester;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\ApiRoute;
use OCP\AppFramework\Http\Attribute\OpenAPI;
use OCP\AppFramework\Http\Attribute\UserRateLimit;
use OCP\AppFramework\Http\DataResponse;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IUserSession;

/**
 * The signatures of the injection probe check and "Test a URL".
 * Administrators only. Nothing here changes anything: signatures are
 * switched and added through the check's settings, and the tests run the
 * matcher on the server without sending a request or recording anything.
 * They take a body because the input can be long, and are rate limited
 * because they run regular expressions.
 *
 * @psalm-import-type IntrusionDetectionSignatures from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionCustomSignature from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionPayloadTest from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionError from ResponseDefinitions
 */
#[OpenAPI(scope: OpenAPI::SCOPE_ADMINISTRATION)]
class PayloadApiController extends AdminOCSController {
	public function __construct(
		IRequest $request,
		IL10N $l,
		IUserSession $userSession,
		private readonly SignaturePresenter $signatures,
		private readonly PayloadTester $tester,
	) {
		parent::__construct($request, $l, $userSession);
	}

	/**
	 * List the signatures of the injection probe check
	 *
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionSignatures, array{}>
	 *
	 * 200: Signatures returned
	 */
	#[ApiRoute(verb: 'GET', url: '/api/v1/payload/signatures')]
	public function signatures(): DataResponse {
		return new DataResponse($this->signatures->catalog($this->l));
	}

	/**
	 * Check custom signatures before saving them
	 *
	 * Runs the same checks as saving, including the test against long input.
	 *
	 * @param list<string> $entries The signatures, each optionally prefixed with a weight and a colon, like "2:union\s+distinct"
	 * @return DataResponse<Http::STATUS_OK, array{entries: list<IntrusionDetectionCustomSignature>}, array{}>|DataResponse<Http::STATUS_BAD_REQUEST, IntrusionDetectionError, array{}>
	 *
	 * 200: Every entry with what is wrong with it, if anything
	 * 400: Too many entries
	 */
	#[ApiRoute(verb: 'POST', url: '/api/v1/payload/signatures/check')]
	#[UserRateLimit(limit: 30, period: 60)]
	public function checkSignatures(array $entries = []): DataResponse {
		$entries = array_values(array_filter(array_map(static fn (mixed $e): string => is_string($e) ? trim($e) : '', $entries), static fn (string $e): bool => $e !== ''));
		if (count($entries) > CustomSignatures::MAX_ITEMS) {
			return $this->error($this->l->t('There can be at most %s custom signatures.', [(string)CustomSignatures::MAX_ITEMS]), 'entries', 'too_many_items');
		}
		return new DataResponse(['entries' => $this->signatures->check($entries, true, $this->l)]);
	}

	/**
	 * Test a URL or a value
	 *
	 * Shows the normalised form, the decoded base64, the signatures that
	 * match with their weights, and whether the check would fire. No request
	 * is sent and nothing is recorded.
	 *
	 * @param string $input A URL (absolute, or a path starting with /), or a single parameter value
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionPayloadTest, array{}>|DataResponse<Http::STATUS_BAD_REQUEST, IntrusionDetectionError, array{}>
	 *
	 * 200: Result returned
	 * 400: The input is empty
	 */
	#[ApiRoute(verb: 'POST', url: '/api/v1/payload/test')]
	#[UserRateLimit(limit: 60, period: 60)]
	public function test(string $input = ''): DataResponse {
		if (trim($input) === '') {
			return $this->error($this->l->t('Paste a web address or a value to test.'), 'input', 'empty');
		}
		return new DataResponse($this->tester->test($input, $this->l));
	}
}
