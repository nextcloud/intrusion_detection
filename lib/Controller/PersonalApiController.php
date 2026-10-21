<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Controller;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCA\IntrusionDetection\TrustedNetwork\TrustedNetworks;
use OCA\IntrusionDetection\WasThisYou\AnswerException;
use OCA\IntrusionDetection\WasThisYou\PersonalDetections;
use OCA\IntrusionDetection\WasThisYou\WasThisYouService;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\ApiRoute;
use OCP\AppFramework\Http\Attribute\NoAdminRequired;
use OCP\AppFramework\Http\Attribute\OpenAPI;
use OCP\AppFramework\Http\Attribute\PasswordConfirmationRequired;
use OCP\AppFramework\Http\Attribute\UserRateLimit;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\OCSController;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IUser;
use OCP\IUserSession;

/**
 * The logged-in user's own security events, their answers to "Was this
 * you?" (also the actions of the user notification) and their trusted
 * networks (concept sections 11.8 and 15.1).
 *
 * Every endpoint only ever touches the current user's own rows: another
 * account's detection or network answers 404, like a missing one. Writes
 * are CSRF-protected (OCS) and rate limited per user; "Yes, it was me"
 * needs a recent password confirmation and is refused from the session the
 * detection is about.
 *
 * @psalm-import-type IntrusionDetectionPersonalDetection from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionTrustedNetwork from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionAnswerError from ResponseDefinitions
 */
#[OpenAPI(scope: OpenAPI::SCOPE_DEFAULT)]
class PersonalApiController extends OCSController {
	public function __construct(
		IRequest $request,
		private readonly IUserSession $userSession,
		private readonly PersonalDetections $detections,
		private readonly WasThisYouService $answers,
		private readonly TrustedNetworks $trustedNetworks,
		private readonly IL10N $l,
	) {
		parent::__construct(Application::APP_ID, $request);
	}

	/**
	 * List the security events of the current user
	 *
	 * @param int<1, 100> $limit at most this many, newest first
	 * @return DataResponse<Http::STATUS_OK, list<IntrusionDetectionPersonalDetection>, array{}>
	 *
	 * 200: The events
	 */
	#[NoAdminRequired]
	#[ApiRoute(verb: 'GET', url: '/api/v1/personal/detections')]
	public function detections(int $limit = 50): DataResponse {
		return new DataResponse($this->detections->forUser($this->user(), $limit));
	}

	/**
	 * Answer "No, it was not me": end the sessions linked to the event, block its address and tell the administrators
	 *
	 * @param int $id the event
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionPersonalDetection, array{}>|DataResponse<Http::STATUS_BAD_REQUEST|Http::STATUS_FORBIDDEN|Http::STATUS_NOT_FOUND|Http::STATUS_CONFLICT, IntrusionDetectionAnswerError, array{}>
	 *
	 * 200: The answer was taken
	 * 400: The event does not ask
	 * 403: The answer cannot be given from this session
	 * 404: There is no such event of the current user
	 * 409: The event was answered already
	 */
	#[NoAdminRequired]
	#[UserRateLimit(limit: 20, period: 600)]
	#[ApiRoute(verb: 'POST', url: '/api/v1/personal/detections/{id}/deny', requirements: ['id' => '\d+'])]
	public function deny(int $id): DataResponse {
		$user = $this->user();
		try {
			return new DataResponse($this->detections->present($this->answers->deny($user, $id), $user));
		} catch (AnswerException $e) {
			return $this->error($e);
		}
	}

	/**
	 * Answer "Yes, it was me": trust the event's network for a while
	 *
	 * @param int $id the event
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionPersonalDetection, array{}>|DataResponse<Http::STATUS_BAD_REQUEST|Http::STATUS_FORBIDDEN|Http::STATUS_NOT_FOUND|Http::STATUS_CONFLICT, IntrusionDetectionAnswerError, array{}>
	 *
	 * 200: The answer was taken
	 * 400: The event does not ask
	 * 403: This session may not answer "Yes" (it is the session the event is about)
	 * 404: There is no such event of the current user
	 * 409: The event was answered already
	 */
	#[NoAdminRequired]
	#[PasswordConfirmationRequired]
	#[UserRateLimit(limit: 20, period: 600)]
	#[ApiRoute(verb: 'POST', url: '/api/v1/personal/detections/{id}/confirm', requirements: ['id' => '\d+'])]
	public function confirm(int $id): DataResponse {
		$user = $this->user();
		try {
			return new DataResponse($this->detections->present($this->answers->confirm($user, $id), $user));
		} catch (AnswerException $e) {
			return $this->error($e);
		}
	}

	/**
	 * List the networks the current user confirmed as their own
	 *
	 * @param int<1, 100> $limit the most networks to return
	 * @return DataResponse<Http::STATUS_OK, list<IntrusionDetectionTrustedNetwork>, array{}>
	 *
	 * 200: The trusted networks, newest first
	 */
	#[NoAdminRequired]
	#[ApiRoute(verb: 'GET', url: '/api/v1/personal/trusted-networks')]
	public function trustedNetworks(int $limit = 100): DataResponse {
		return new DataResponse($this->trustedNetworks->forUser($this->user()->getUID(), max(1, min(100, $limit))));
	}

	/**
	 * Stop trusting one of the current user's networks
	 *
	 * @param int $id the entry
	 * @return DataResponse<Http::STATUS_OK, array{removed: int}, array{}>|DataResponse<Http::STATUS_NOT_FOUND, IntrusionDetectionAnswerError, array{}>
	 *
	 * 200: Removed
	 * 404: The current user has no such entry
	 */
	#[NoAdminRequired]
	#[UserRateLimit(limit: 20, period: 600)]
	#[ApiRoute(verb: 'DELETE', url: '/api/v1/personal/trusted-networks/{id}', requirements: ['id' => '\d+'])]
	public function removeTrustedNetwork(int $id): DataResponse {
		$uid = $this->user()->getUID();
		if (!$this->trustedNetworks->remove($uid, $id)) {
			return new DataResponse(['reason' => AnswerException::NOT_FOUND, 'message' => $this->l->t('This network is not one of your trusted networks.')], Http::STATUS_NOT_FOUND);
		}
		return new DataResponse(['removed' => $id]);
	}

	private function user(): IUser {
		$user = $this->userSession->getUser();
		if ($user === null) {
			// The AppFramework lets only logged-in users reach these endpoints.
			throw new \LogicException('Not logged in');
		}
		return $user;
	}

	/**
	 * @return DataResponse<Http::STATUS_BAD_REQUEST|Http::STATUS_FORBIDDEN|Http::STATUS_NOT_FOUND|Http::STATUS_CONFLICT, IntrusionDetectionAnswerError, array{}>
	 */
	private function error(AnswerException $e): DataResponse {
		[$status, $message] = match ($e->reason) {
			AnswerException::NOT_FOUND => [Http::STATUS_NOT_FOUND, $this->l->t('This event does not exist, or it is not about your account.')],
			AnswerException::NOT_ASKED => [Http::STATUS_BAD_REQUEST, $this->l->t('This event does not need an answer.')],
			AnswerException::ANSWERED => [Http::STATUS_CONFLICT, $this->l->t('This event was answered already.')],
			default => [Http::STATUS_FORBIDDEN, $this->l->t('For your safety, "Yes, it was me" cannot be answered from the session this event is about, or from a login that was not confirmed. Answer from another device or a confirmed login.')],
		};
		return new DataResponse(['reason' => $e->reason, 'message' => $message], $status);
	}
}
