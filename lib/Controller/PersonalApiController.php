<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Controller;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\LoginHistoryMapper;
use OCA\IntrusionDetection\Db\SecurityChangeMapper;
use OCA\IntrusionDetection\Guide\SecureAccountGuide;
use OCA\IntrusionDetection\Guide\SecureAccountOverview;
use OCA\IntrusionDetection\KnownDevice\KnownDevices;
use OCA\IntrusionDetection\LoginHistory\LoginHistoryEntry;
use OCA\IntrusionDetection\Personal\LogOutElsewhere;
use OCA\IntrusionDetection\Personal\PersonalActivity;
use OCA\IntrusionDetection\Personal\PersonalOverview;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCA\IntrusionDetection\SessionState\CurrentSession;
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
use OCP\AppFramework\OCS\OCSNotFoundException;
use OCP\AppFramework\OCSController;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IUser;
use OCP\IUserSession;

/**
 * The logged-in user's own security events, their answers to
 * "Was this you?" (also the actions of the user notification), their
 * trusted networks, their remembered devices, their recent logins, the
 * overview at the top of their security section, their recent activity
 * and "Log out everywhere else" (concept sections 11.5.1, 11.8 and 15.1).
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
 * @psalm-import-type IntrusionDetectionKnownDevice from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionLogin from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionSecurityChange from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionSecureAccount from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionSecureAccountProgress from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionPersonalOverview from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionLoggedOutElsewhere from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionPersonalActivity from ResponseDefinitions
 */
#[OpenAPI(scope: OpenAPI::SCOPE_DEFAULT)]
class PersonalApiController extends OCSController {
	/** The request is not a browser session of the user */
	public const NO_SESSION = 'no_session';

	public function __construct(
		IRequest $request,
		private readonly IUserSession $userSession,
		private readonly PersonalDetections $detections,
		private readonly WasThisYouService $answers,
		private readonly TrustedNetworks $trustedNetworks,
		private readonly IL10N $l,
		private readonly KnownDevices $knownDevices,
		private readonly LoginHistoryMapper $loginHistory,
		private readonly CurrentSession $currentSession,
		private readonly SecureAccountGuide $guide,
		private readonly SecureAccountOverview $overview,
		private readonly SecurityChangeMapper $changes,
		private readonly Settings $settings,
		private readonly ITimeFactory $timeFactory,
		private readonly PersonalOverview $personalOverview,
		private readonly LogOutElsewhere $logOutElsewhere,
		private readonly PersonalActivity $activity,
	) {
		parent::__construct(Application::APP_ID, $request);
	}

	/**
	 * List the security events of the current user
	 *
	 * @param int<1, 100> $limit at most this many, newest first
	 * @return DataResponse<Http::STATUS_OK, list<IntrusionDetectionPersonalDetection>, array{}>
	 * @throws OCSNotFoundException The security page is switched off
	 *
	 * 200: The events
	 */
	#[NoAdminRequired]
	#[ApiRoute(verb: 'GET', url: '/api/v1/personal/detections')]
	public function detections(int $limit = 50): DataResponse {
		$this->requirePage();
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
	 * @throws OCSNotFoundException The security page is switched off
	 *
	 * 200: The trusted networks, newest first
	 */
	#[NoAdminRequired]
	#[ApiRoute(verb: 'GET', url: '/api/v1/personal/trusted-networks')]
	public function trustedNetworks(int $limit = 100): DataResponse {
		$this->requirePage();
		return new DataResponse($this->trustedNetworks->forUser($this->user()->getUID(), max(1, min(100, $limit))));
	}

	/**
	 * Stop trusting one of the current user's networks
	 *
	 * @param int $id the entry
	 * @return DataResponse<Http::STATUS_OK, array{removed: int}, array{}>|DataResponse<Http::STATUS_NOT_FOUND, IntrusionDetectionAnswerError, array{}>
	 * @throws OCSNotFoundException The security page is switched off
	 *
	 * 200: Removed
	 * 404: The current user has no such entry
	 */
	#[NoAdminRequired]
	#[UserRateLimit(limit: 20, period: 600)]
	#[ApiRoute(verb: 'DELETE', url: '/api/v1/personal/trusted-networks/{id}', requirements: ['id' => '\d+'])]
	public function removeTrustedNetwork(int $id): DataResponse {
		$this->requirePage();
		$uid = $this->user()->getUID();
		if (!$this->trustedNetworks->remove($uid, $id)) {
			return new DataResponse(['reason' => AnswerException::NOT_FOUND, 'message' => $this->l->t('This network is not one of your trusted networks.')], Http::STATUS_NOT_FOUND);
		}
		return new DataResponse(['removed' => $id]);
	}

	/**
	 * List the browsers the current user remembered
	 *
	 * @param int<1, 50> $limit the most devices to return
	 * @return DataResponse<Http::STATUS_OK, list<IntrusionDetectionKnownDevice>, array{}>
	 * @throws OCSNotFoundException The security page is switched off
	 *
	 * 200: The devices, most recently used first; `current` marks the browser of this request
	 */
	#[NoAdminRequired]
	#[ApiRoute(verb: 'GET', url: '/api/v1/personal/known-devices')]
	public function knownDevices(int $limit = 50): DataResponse {
		$this->requirePage();
		return new DataResponse($this->knownDevices->forUser($this->user()->getUID(), $this->l, max(1, min(KnownDevices::MAX_PER_USER, $limit))));
	}

	/**
	 * Forget one of the current user's remembered browsers
	 *
	 * Its logins are asked for a confirmation again where needed.
	 *
	 * @param int $id the device
	 * @return DataResponse<Http::STATUS_OK, array{removed: int}, array{}>|DataResponse<Http::STATUS_NOT_FOUND, IntrusionDetectionAnswerError, array{}>
	 * @throws OCSNotFoundException The security page is switched off
	 *
	 * 200: Forgotten
	 * 404: The current user has no such device
	 */
	#[NoAdminRequired]
	#[UserRateLimit(limit: 20, period: 600)]
	#[ApiRoute(verb: 'DELETE', url: '/api/v1/personal/known-devices/{id}', requirements: ['id' => '\d+'])]
	public function removeKnownDevice(int $id): DataResponse {
		$this->requirePage();
		if (!$this->knownDevices->remove($this->user()->getUID(), $id)) {
			return new DataResponse(['reason' => AnswerException::NOT_FOUND, 'message' => $this->l->t('This device is not one of your remembered devices.')], Http::STATUS_NOT_FOUND);
		}
		return new DataResponse(['removed' => $id]);
	}

	/**
	 * List the current user's recent logins
	 *
	 * @param int<1, 365> $days how far back, at most as long as the history is kept
	 * @param int<1, 200> $limit the most logins to return
	 * @return DataResponse<Http::STATUS_OK, list<IntrusionDetectionLogin>, array{}>
	 * @throws OCSNotFoundException The security page is switched off
	 *
	 * 200: The logins, newest first; `current` marks the login of this session
	 */
	#[NoAdminRequired]
	#[ApiRoute(verb: 'GET', url: '/api/v1/personal/logins')]
	public function logins(int $days = 30, int $limit = 100): DataResponse {
		$this->requirePage();
		$days = max(1, min($days, $this->settings->getInt(GlobalSettings::HISTORY_RETENTION_DAYS)));
		$current = $this->currentSession->tokenId();
		$entries = $this->loginHistory->forUser($this->user()->getUID(), $this->timeFactory->getTime() - $days * 86400, null, max(1, min(200, $limit)));
		$l = $this->l;
		return new DataResponse(array_map(static fn (LoginHistoryEntry $e): array => PersonalActivity::login($e, $current, $l), $entries));
	}

	/**
	 * Get the recent activity of the current user: the open "Was this you?" questions, and one timeline of logins, security changes, days with failed logins and the other security events
	 *
	 * @param int<1, 365> $days how far back the timeline goes
	 * @param int<1, 100> $limit the most timeline entries
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionPersonalActivity, array{}>
	 * @throws OCSNotFoundException The security page is switched off
	 *
	 * 200: The open questions and the timeline, newest first; `hasMore` when older entries exist
	 */
	#[NoAdminRequired]
	#[ApiRoute(verb: 'GET', url: '/api/v1/personal/activity')]
	public function activity(int $days = 30, int $limit = 30): DataResponse {
		$this->requirePage();
		return new DataResponse($this->activity->forUser($this->user(), $this->l, $days, $limit));
	}

	/**
	 * List the recent security changes of the current user: email address, password, second factor and app passwords
	 *
	 * @param int<1, 100> $limit at most this many, newest first
	 * @return DataResponse<Http::STATUS_OK, list<IntrusionDetectionSecurityChange>, array{}>
	 * @throws OCSNotFoundException The security page is switched off
	 *
	 * 200: The changes, as long as they are kept
	 */
	#[NoAdminRequired]
	#[ApiRoute(verb: 'GET', url: '/api/v1/personal/security-changes')]
	public function securityChanges(int $limit = 50): DataResponse {
		$this->requirePage();
		$since = $this->timeFactory->getTime() - $this->settings->getInt(GlobalSettings::HISTORY_RETENTION_DAYS) * 86400;
		$rows = $this->changes->findRecent($this->user()->getUID(), $since, max(1, min(100, $limit)));
		return new DataResponse(array_map(fn (array $row): array => SecureAccountOverview::change($row, $this->l), $rows));
	}

	/**
	 * Get the "Secure my account" checklist of the current user, with what each step shows
	 *
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionSecureAccount, array{}>
	 *
	 * 200: The checklist; `progress.active` is false when none is open
	 */
	#[NoAdminRequired]
	#[ApiRoute(verb: 'GET', url: '/api/v1/personal/secure-account')]
	public function secureAccount(): DataResponse {
		return new DataResponse($this->overview->forUser($this->user(), $this->l));
	}

	/**
	 * Get only the progress through the "Secure my account" checklist of the current user
	 *
	 * For the card on the personal security page, which needs nothing else:
	 * the full checklist also lists every session and share.
	 *
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionSecureAccountProgress, array{}>
	 * @throws OCSNotFoundException The security page is switched off
	 *
	 * 200: The progress; `active` is false when no checklist is open
	 */
	#[NoAdminRequired]
	#[ApiRoute(verb: 'GET', url: '/api/v1/personal/secure-account/progress')]
	public function secureAccountProgress(): DataResponse {
		$this->requirePage();
		return new DataResponse($this->guide->progress($this->user()));
	}

	/**
	 * Start the "Secure my account" checklist, or keep the open one
	 *
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionSecureAccount, array{}>
	 *
	 * 200: The checklist
	 */
	#[NoAdminRequired]
	#[UserRateLimit(limit: 10, period: 600)]
	#[ApiRoute(verb: 'POST', url: '/api/v1/personal/secure-account')]
	public function startSecureAccount(): DataResponse {
		$user = $this->user();
		if (!$this->guide->isOpen($user->getUID())) {
			$this->guide->start($user->getUID(), SecureAccountGuide::REASON_SELF);
		}
		return new DataResponse($this->overview->forUser($user, $this->l));
	}

	/**
	 * Mark a step of the checklist done that the user checks themselves
	 *
	 * @param string $step sessions, email, shares or files
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionSecureAccount, array{}>|DataResponse<Http::STATUS_BAD_REQUEST|Http::STATUS_CONFLICT, IntrusionDetectionAnswerError, array{}>
	 *
	 * 200: The step is done
	 * 400: The user cannot mark this step
	 * 409: No checklist is open
	 */
	#[NoAdminRequired]
	#[UserRateLimit(limit: 30, period: 600)]
	#[ApiRoute(verb: 'POST', url: '/api/v1/personal/secure-account/steps/{step}', requirements: ['step' => '[a-z_]{1,32}'])]
	public function completeSecureAccountStep(string $step): DataResponse {
		$user = $this->user();
		if (!in_array($step, SecureAccountGuide::USER_STEPS, true)) {
			return new DataResponse(['reason' => 'not_a_user_step', 'message' => $this->l->t('This step is done by itself once you have done it.')], Http::STATUS_BAD_REQUEST);
		}
		if (!$this->guide->markDone($user->getUID(), $step)) {
			return new DataResponse(['reason' => 'not_open', 'message' => $this->l->t('There is no open checklist. Start it again to go through it.')], Http::STATUS_CONFLICT);
		}
		return new DataResponse($this->overview->forUser($user, $this->l));
	}

	/**
	 * Close the checklist without finishing it
	 *
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionSecureAccount, array{}>
	 *
	 * 200: Closed, or none was open
	 */
	#[NoAdminRequired]
	#[UserRateLimit(limit: 10, period: 600)]
	#[ApiRoute(verb: 'DELETE', url: '/api/v1/personal/secure-account')]
	public function dismissSecureAccount(): DataResponse {
		$user = $this->user();
		$this->guide->dismiss($user->getUID());
		return new DataResponse($this->overview->forUser($user, $this->l));
	}

	/**
	 * The status, failed logins and hints at the top of the current user's security section
	 *
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionPersonalOverview, array{}>
	 * @throws OCSNotFoundException The security page is switched off
	 *
	 * 200: The overview
	 */
	#[NoAdminRequired]
	#[ApiRoute(verb: 'GET', url: '/api/v1/personal/overview')]
	public function overview(): DataResponse {
		$this->requirePage();
		return new DataResponse($this->personalOverview->get($this->user(), $this->l));
	}

	/**
	 * Log out everywhere else: end every other browser session of the current user and forget the other remembered browsers
	 *
	 * App passwords and connected devices keep working.
	 *
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionLoggedOutElsewhere, array{}>|DataResponse<Http::STATUS_BAD_REQUEST, IntrusionDetectionAnswerError, array{}>
	 * @throws OCSNotFoundException The security page is switched off
	 *
	 * 200: Logged out everywhere else
	 * 400: Only a browser session can do this, not an app password
	 */
	#[NoAdminRequired]
	#[PasswordConfirmationRequired]
	#[UserRateLimit(limit: 5, period: 3600)]
	#[ApiRoute(verb: 'POST', url: '/api/v1/personal/log-out-elsewhere')]
	public function logOutElsewhere(): DataResponse {
		$this->requirePage();
		$result = $this->logOutElsewhere->run($this->user());
		if ($result === null) {
			return new DataResponse(['reason' => self::NO_SESSION, 'message' => $this->l->t('This can only be done from a browser session, not with an app password.')], Http::STATUS_BAD_REQUEST);
		}
		return new DataResponse($result);
	}

	/**
	 * The endpoints of the security page answer only while the page is
	 * shown. Answers to "Was this you?" stay reachable from notifications.
	 *
	 * @throws OCSNotFoundException
	 */
	private function requirePage(): void {
		if (!$this->settings->personalPageEnabled()) {
			throw new OCSNotFoundException();
		}
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
