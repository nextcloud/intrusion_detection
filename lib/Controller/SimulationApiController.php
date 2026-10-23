<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Controller;

use OCA\IntrusionDetection\AdminChange\ActorResolver;
use OCA\IntrusionDetection\Detection\Simulator;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\ApiRoute;
use OCP\AppFramework\Http\Attribute\OpenAPI;
use OCP\AppFramework\Http\Attribute\UserRateLimit;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\OCS\OCSNotFoundException;
use OCP\IL10N;
use OCP\IRequest;

/**
 * "Simulate" on the check cards. Administrators only. A simulation only
 * reads the settings: nothing is recorded, blocked or notified.
 *
 * @psalm-import-type IntrusionDetectionSimulation from ResponseDefinitions
 */
#[OpenAPI(scope: OpenAPI::SCOPE_ADMINISTRATION)]
class SimulationApiController extends AdminOCSController {
	public function __construct(
		IRequest $request,
		IL10N $l,
		ActorResolver $actors,
		private readonly Simulator $simulator,
	) {
		parent::__construct($request, $l, $actors);
	}

	/**
	 * Simulate an attack on a check
	 *
	 * What the check would report and do for an attack that just reaches its
	 * current thresholds, from an address of the documentation range
	 * 198.51.100.0/24.
	 *
	 * @param string $id The check id
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionSimulation, array{}>
	 * @throws OCSNotFoundException The check does not exist or cannot be simulated
	 *
	 * 200: Simulation returned
	 */
	#[ApiRoute(verb: 'GET', url: '/api/v1/checks/{id}/simulation', requirements: ['id' => '[a-z][a-z0-9_]{2,31}'])]
	#[UserRateLimit(limit: 60, period: 60)]
	public function simulate(string $id): DataResponse {
		if (!$this->simulator->canSimulate($id)) {
			throw new OCSNotFoundException($this->l->t('This check cannot be simulated.'));
		}
		return new DataResponse($this->simulator->simulate($id, $this->l));
	}
}
