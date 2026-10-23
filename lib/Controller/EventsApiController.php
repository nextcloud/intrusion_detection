<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Controller;

use OCA\IntrusionDetection\AdminChange\ActorResolver;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Event\EventExamples;
use OCA\IntrusionDetection\Event\TypedEvents;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\App\IAppManager;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\ApiRoute;
use OCP\AppFramework\Http\Attribute\OpenAPI;
use OCP\AppFramework\Http\DataResponse;
use OCP\IL10N;
use OCP\IRequest;

/**
 * The admin page's API for the typed events that webhooks can receive.
 * Administrators only, like the rest of the admin API.
 *
 * @psalm-import-type IntrusionDetectionWebhookEvents from ResponseDefinitions
 */
#[OpenAPI(scope: OpenAPI::SCOPE_ADMINISTRATION)]
class EventsApiController extends AdminOCSController {
	public function __construct(
		IRequest $request,
		IL10N $l,
		ActorResolver $actors,
		private readonly EventExamples $examples,
		private readonly AppSettings $settings,
		private readonly IAppManager $appManager,
	) {
		parent::__construct($request, $l, $actors);
	}

	/**
	 * List the events for webhooks, with example payloads
	 *
	 * The examples are built from real event objects and follow the current
	 * setting for addresses in events.
	 *
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionWebhookEvents, array{}>
	 *
	 * 200: Events returned
	 */
	#[ApiRoute(verb: 'GET', url: '/api/v1/events')]
	public function events(): DataResponse {
		return new DataResponse([
			'includeIp' => $this->settings->eventsIncludeIp(),
			'webhooksEnabled' => $this->appManager->isEnabledForAnyone(TypedEvents::WEBHOOK_APP),
			'events' => $this->examples->all($this->l),
		]);
	}
}
