<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Controller;

use OCA\IntrusionDetection\AdminChange\ActorResolver;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Response\Tokens;
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
 * Ends every session and app password of the account a detection is
 * about, for an administrator who handles the detection.
 */
#[OpenAPI(scope: OpenAPI::SCOPE_ADMINISTRATION)]
class AccountSessionsController extends AdminOCSController {
	public function __construct(
		IRequest $request,
		IL10N $l,
		ActorResolver $actors,
		private readonly DetectionMapper $detections,
		private readonly IUserManager $userManager,
		private readonly Tokens $tokens,
		private readonly AuditLogger $audit,
	) {
		parent::__construct($request, $l, $actors);
	}

	/**
	 * End every session and app password of a detection's account
	 *
	 * The account's browsers are logged out and its apps must be connected again.
	 *
	 * @param int $id A detection about the account
	 * @return DataResponse<Http::STATUS_OK, array{ended: int}, array{}>
	 * @throws OCSNotFoundException The detection does not exist, is not about an account, or the account is gone
	 *
	 * 200: The number of sessions and app passwords ended
	 */
	#[ApiRoute(verb: 'POST', url: '/api/v1/detections/{id}/sessions/end', requirements: ['id' => '\d+'])]
	#[PasswordConfirmationRequired]
	public function end(int $id): DataResponse {
		$detection = $this->found(fn () => $this->detections->findById($id), $this->l->t('This detection does not exist (any more).'));
		$uid = $detection->getUid();
		if ($uid === null) {
			throw new OCSNotFoundException($this->l->t('This detection is not about an account.'));
		}
		if ($this->userManager->get($uid) === null) {
			throw new OCSNotFoundException($this->l->t('The account does not exist any more.'));
		}
		$ended = count($this->tokens->invalidateAll($uid));
		$this->audit->log('%s ended %s sessions and app passwords of %s (detection %s)', ['actor' => $this->actor(), 'count' => $ended, 'uid' => $uid, 'detection' => $id]);
		return new DataResponse(['ended' => $ended]);
	}
}
