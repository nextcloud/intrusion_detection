<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Controller;

use OCA\IntrusionDetection\Admin\GlobalSettingsPresenter;
use OCA\IntrusionDetection\Admin\SettingsTransfer;
use OCA\IntrusionDetection\Admin\StatusService;
use OCA\IntrusionDetection\AdminChange\ActorResolver;
use OCA\IntrusionDetection\Learning\LearningService;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\ApiRoute;
use OCP\AppFramework\Http\Attribute\OpenAPI;
use OCP\AppFramework\Http\Attribute\PasswordConfirmationRequired;
use OCP\AppFramework\Http\DataResponse;
use OCP\IL10N;
use OCP\IRequest;

/**
 * The global settings and learning mode on the admin page, with the
 * export for support and the reset to the defaults. Administrators only;
 * every change needs a recent password confirmation and is written to the
 * audit log.
 *
 * @psalm-import-type IntrusionDetectionLearning from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionSettings from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionExport from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionError from ResponseDefinitions
 */
#[OpenAPI(scope: OpenAPI::SCOPE_ADMINISTRATION)]
class SettingsApiController extends AdminOCSController {
	public function __construct(
		IRequest $request,
		IL10N $l,
		ActorResolver $actors,
		private readonly StatusService $status,
		private readonly LearningService $learningService,
		private readonly GlobalSettingsPresenter $globalSettings,
		private readonly SettingsTransfer $transfer,
	) {
		parent::__construct($request, $l, $actors);
	}

	/**
	 * Show learning mode
	 *
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionLearning, array{}>
	 *
	 * 200: Learning mode returned
	 */
	#[ApiRoute(verb: 'GET', url: '/api/v1/learning')]
	public function learning(): DataResponse {
		return new DataResponse($this->status->learning());
	}

	/**
	 * Start, extend or end learning mode
	 *
	 * While learning, checks set to Protect only observe.
	 *
	 * @param 'start'|'extend'|'stop' $action What to do
	 * @param int<1, 30> $days For start and extend: the number of days
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionLearning, array{}>|DataResponse<Http::STATUS_BAD_REQUEST, IntrusionDetectionError, array{}>
	 *
	 * 200: Learning mode changed
	 * 400: The action or the number of days is not valid, or the learning period would last more than 30 days in all
	 */
	#[ApiRoute(verb: 'PUT', url: '/api/v1/learning')]
	#[PasswordConfirmationRequired]
	public function updateLearning(string $action, int $days = 7): DataResponse {
		if ($action === 'stop') {
			$this->learningService->stop($this->actor());
			return new DataResponse($this->status->learning());
		}
		if ($action !== 'start' && $action !== 'extend') {
			return $this->error($this->l->t('Choose to start, extend or stop learning mode.'), 'action', 'invalid_action');
		}
		if ($days < LearningService::MIN_DAYS || $days > LearningService::MAX_DAYS) {
			return $this->error($this->l->t('Learning mode lasts 1 to 30 days.'), 'days', 'invalid_days');
		}
		if ($action === 'start') {
			$this->learningService->start($days, $this->actor());
		} else {
			$this->learningService->extend($days, $this->actor());
		}
		return new DataResponse($this->status->learning());
	}

	/**
	 * List the global settings
	 *
	 * Every setting an administrator may change, with its rules and texts,
	 * and the explanation templates that use them.
	 *
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionSettings, array{}>
	 *
	 * 200: Settings returned
	 */
	#[ApiRoute(verb: 'GET', url: '/api/v1/settings')]
	public function settings(): DataResponse {
		return new DataResponse($this->globalSettings->present($this->l));
	}

	/**
	 * Change global settings
	 *
	 * Every given value is validated before anything is saved.
	 *
	 * @param array<string, mixed> $values New values by setting name; durations in seconds or as text like "4h"
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionSettings, array{}>|DataResponse<Http::STATUS_BAD_REQUEST, IntrusionDetectionError, array{}>
	 *
	 * 200: Settings changed
	 * 400: A value is not valid; nothing was saved
	 */
	#[ApiRoute(verb: 'PUT', url: '/api/v1/settings')]
	#[PasswordConfirmationRequired]
	public function updateSettings(array $values = []): DataResponse {
		$this->transfer->changeSettings($values, $this->actor());
		return new DataResponse($this->globalSettings->present($this->l));
	}

	/**
	 * Put every check and global setting back to its default
	 *
	 * Learning mode, blocks and detections are not touched.
	 *
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionSettings, array{}>
	 *
	 * 200: Settings reset
	 */
	#[ApiRoute(verb: 'POST', url: '/api/v1/settings/reset')]
	#[PasswordConfirmationRequired]
	public function resetSettings(): DataResponse {
		$this->transfer->resetAll($this->actor());
		return new DataResponse($this->globalSettings->present($this->l));
	}

	/**
	 * Export the settings as JSON, for support
	 *
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionExport, array{}>
	 *
	 * 200: Settings returned
	 */
	#[ApiRoute(verb: 'GET', url: '/api/v1/settings/export')]
	public function exportSettings(): DataResponse {
		return new DataResponse($this->transfer->export());
	}

}
