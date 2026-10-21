<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Controller;

use OCA\IntrusionDetection\Admin\LockdownOverview;
use OCA\IntrusionDetection\Check\InvalidParamException;
use OCA\IntrusionDetection\Lockdown\LockdownEffect;
use OCA\IntrusionDetection\Lockdown\LockdownException;
use OCA\IntrusionDetection\Lockdown\LockdownService;
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
 * Lockdown mode on the admin page (concept section 11.14): start it with a
 * duration, a reason and its effects, extend it, end it. Administrators
 * only; every change needs a recent password confirmation and is audited.
 *
 * None of these routes is a sensitive action, and none depends on anything
 * a lockdown blocks: an administrator can always end a lockdown here, and
 * with occ.
 *
 * @psalm-import-type IntrusionDetectionLockdown from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionError from ResponseDefinitions
 */
#[OpenAPI(scope: OpenAPI::SCOPE_ADMINISTRATION)]
class LockdownApiController extends AdminOCSController {
	public function __construct(
		IRequest $request,
		IL10N $l,
		IUserSession $userSession,
		private readonly LockdownService $lockdown,
		private readonly LockdownOverview $overview,
	) {
		parent::__construct($request, $l, $userSession);
	}

	/**
	 * Show lockdown mode
	 *
	 * Whether it is on and until when, who started it and why, its effects,
	 * the accounts that cannot log in with their password during it, and
	 * the latest lockdowns.
	 *
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionLockdown, array{}>
	 *
	 * 200: Lockdown mode returned
	 */
	#[ApiRoute(verb: 'GET', url: '/api/v1/lockdown')]
	public function index(): DataResponse {
		return new DataResponse($this->overview->get($this->l));
	}

	/**
	 * Start a lockdown
	 *
	 * @param int $duration How long it lasts, in seconds: 1 to 24 hours
	 * @param string $reason Why, for the other administrators and the audit log; at most 200 characters
	 * @param list<string>|null $effects The effects to switch on; null keeps the configured ones
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionLockdown, array{}>|DataResponse<Http::STATUS_BAD_REQUEST, IntrusionDetectionError, array{}>
	 *
	 * 200: Lockdown started
	 * 400: The duration, reason or effects are not valid, or a lockdown is running already
	 */
	#[ApiRoute(verb: 'POST', url: '/api/v1/lockdown')]
	#[PasswordConfirmationRequired]
	public function start(int $duration, string $reason = '', ?array $effects = null): DataResponse {
		if ($duration < LockdownEffect::MIN_DURATION || $duration > LockdownEffect::MAX_DURATION) {
			return $this->error($this->l->t('A lockdown lasts 1 to 24 hours.'), 'duration', 'invalid_duration');
		}
		if (strlen($reason) > LockdownEffect::MAX_REASON) {
			return $this->error($this->l->t('The reason can be at most %s characters long.', [(string)LockdownEffect::MAX_REASON]), 'reason', 'invalid_reason');
		}
		if ($effects !== null) {
			$effects = array_values(array_filter($effects, 'is_string'));
		}
		try {
			$this->lockdown->start($duration, $reason, $this->actor(), $effects);
		} catch (InvalidParamException $e) {
			return $this->invalid($e);
		} catch (LockdownException) {
			return $this->error($this->l->t('A lockdown is running already. Extend it instead.'), null, 'running');
		}
		return new DataResponse($this->overview->get($this->l));
	}

	/**
	 * Extend the running lockdown
	 *
	 * At most to 24 hours from now.
	 *
	 * @param int $extend By how much, in seconds: 1 to 24 hours
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionLockdown, array{}>|DataResponse<Http::STATUS_BAD_REQUEST, IntrusionDetectionError, array{}>
	 *
	 * 200: Lockdown extended
	 * 400: The extension is not valid, or no lockdown is running
	 */
	#[ApiRoute(verb: 'PUT', url: '/api/v1/lockdown')]
	#[PasswordConfirmationRequired]
	public function extend(int $extend): DataResponse {
		if ($extend < LockdownEffect::MIN_DURATION || $extend > LockdownEffect::MAX_DURATION) {
			return $this->error($this->l->t('A lockdown is extended by 1 to 24 hours.'), 'extend', 'invalid_duration');
		}
		try {
			$this->lockdown->extend($extend, $this->actor());
		} catch (LockdownException) {
			return $this->error($this->l->t('No lockdown is running.'), null, 'not_running');
		}
		return new DataResponse($this->overview->get($this->l));
	}

	/**
	 * End the running lockdown
	 *
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionLockdown, array{}>
	 *
	 * 200: Lockdown ended, or none was running
	 */
	#[ApiRoute(verb: 'DELETE', url: '/api/v1/lockdown')]
	#[PasswordConfirmationRequired]
	public function end(): DataResponse {
		$this->lockdown->end($this->actor());
		return new DataResponse($this->overview->get($this->l));
	}
}
