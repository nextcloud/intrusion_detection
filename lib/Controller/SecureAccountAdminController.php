<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Controller;

use OCA\IntrusionDetection\AdminChange\ActorResolver;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\Checks\AccountLocked\AccountLocked;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Guide\SecureAccountGuide;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCA\IntrusionDetection\Takeover\AccountLock;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\ApiRoute;
use OCP\AppFramework\Http\Attribute\OpenAPI;
use OCP\AppFramework\Http\Attribute\PasswordConfirmationRequired;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\OCS\OCSNotFoundException;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IUserManager;

/**
 * The "Secure my account" state of a detection's account on the admin
 * page (concept sections 11.15 and 15.3): the checklist's progress, and for
 * accounts locked with the lock link "Re-enable and start Secure my
 * account". Administrators only; every write needs password confirmation
 * and is audited.
 *
 * @psalm-import-type IntrusionDetectionAccountGuide from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionError from ResponseDefinitions
 */
#[OpenAPI(scope: OpenAPI::SCOPE_ADMINISTRATION)]
class SecureAccountAdminController extends AdminOCSController {
	public function __construct(
		IRequest $request,
		IL10N $l,
		ActorResolver $actors,
		private readonly DetectionMapper $detections,
		private readonly SecureAccountGuide $guide,
		private readonly AccountLock $lock,
		private readonly IUserManager $userManager,
		private readonly AuditLogger $audit,
	) {
		parent::__construct($request, $l, $actors);
	}

	/**
	 * Get the "Secure my account" state of a detection's account
	 *
	 * @param int $id The detection
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionAccountGuide, array{}>
	 * @throws OCSNotFoundException The detection does not exist or is not about an account
	 *
	 * 200: The account's state
	 */
	#[ApiRoute(verb: 'GET', url: '/api/v1/detections/{id}/secure-account', requirements: ['id' => '\d+'])]
	public function show(int $id): DataResponse {
		return new DataResponse($this->present($this->detection($id)));
	}

	/**
	 * Enable an account that was locked with the lock link, and start "Secure my account" for its owner
	 *
	 * @param int $id The detection of the lock
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionAccountGuide, array{}>|DataResponse<Http::STATUS_BAD_REQUEST, IntrusionDetectionError, array{}>
	 * @throws OCSNotFoundException The detection does not exist or is not about an account
	 *
	 * 200: The account is enabled again
	 * 400: The detection is not a lock, or the account is not disabled
	 */
	#[ApiRoute(verb: 'POST', url: '/api/v1/detections/{id}/reenable', requirements: ['id' => '\d+'])]
	#[PasswordConfirmationRequired]
	public function reenable(int $id): DataResponse {
		$detection = $this->detection($id);
		return match ($this->lock->reenable($detection, $this->actor())) {
			AccountLock::REENABLED => new DataResponse($this->present($detection)),
			AccountLock::NOT_LOCKED => $this->error($this->l->t('The account is enabled already.'), null, AccountLock::NOT_LOCKED),
			AccountLock::NO_ACCOUNT => throw new OCSNotFoundException($this->l->t('The account does not exist any more.')),
			default => $this->error($this->l->t('Only accounts locked with the lock link can be enabled here. Use the account management for others.'), null, AccountLock::NOT_A_LOCK),
		};
	}

	/**
	 * Mark the password step done for an account whose password is managed outside Nextcloud
	 *
	 * @param int $id A detection of the account
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionAccountGuide, array{}>|DataResponse<Http::STATUS_BAD_REQUEST, IntrusionDetectionError, array{}>
	 * @throws OCSNotFoundException The detection does not exist or is not about an account
	 *
	 * 200: The step is done
	 * 400: Nextcloud manages this password, or no checklist is open
	 */
	#[ApiRoute(verb: 'POST', url: '/api/v1/detections/{id}/secure-account/password', requirements: ['id' => '\d+'])]
	#[PasswordConfirmationRequired]
	public function passwordReset(int $id): DataResponse {
		$detection = $this->detection($id);
		$user = $this->userManager->get((string)$detection->getUid());
		if ($user === null) {
			throw new OCSNotFoundException($this->l->t('The account does not exist any more.'));
		}
		if ($user->canChangePassword()) {
			return $this->error($this->l->t('Nextcloud manages this password: the step is done when the user chooses a new one.'), null, 'managed_here');
		}
		if (!$this->guide->markDone($user->getUID(), SecureAccountGuide::STEP_PASSWORD)) {
			return $this->error($this->l->t('The user has no open "Secure my account" checklist.'), null, 'not_open');
		}
		$this->audit->log('%s confirmed that the password of %s was reset in the external directory', ['actor' => $this->actor(), 'uid' => $user->getUID()]);
		return new DataResponse($this->present($detection));
	}

	private function detection(int $id): Detection {
		$detection = $this->found(fn () => $this->detections->findById($id), $this->l->t('This detection does not exist (any more).'));
		if ($detection->getUid() === null) {
			throw new OCSNotFoundException($this->l->t('This detection is not about an account.'));
		}
		return $detection;
	}

	/**
	 * @return IntrusionDetectionAccountGuide
	 */
	private function present(Detection $detection): array {
		$uid = (string)$detection->getUid();
		$user = $this->userManager->get($uid);
		$locked = $detection->getCheckId() === AccountLocked::ID;
		$progress = $user === null ? null : $this->guide->progress($user);
		return [
			'uid' => $uid,
			'displayName' => $user?->getDisplayName() ?? $uid,
			'exists' => $user !== null,
			'enabled' => $user?->isEnabled() ?? false,
			'lockedByLink' => $locked,
			'canReenable' => $locked && $user !== null && !$user->isEnabled(),
			'progress' => $progress !== null && $progress['startedAt'] !== null ? $progress : null,
		];
	}
}
