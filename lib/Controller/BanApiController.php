<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Controller;

use OCA\IntrusionDetection\Admin\BanPresenter;
use OCA\IntrusionDetection\AdminChange\ActorResolver;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Response\BanService;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\ApiRoute;
use OCP\AppFramework\Http\Attribute\OpenAPI;
use OCP\AppFramework\Http\Attribute\PasswordConfirmationRequired;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\OCS\OCSNotFoundException;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IL10N;
use OCP\IRequest;

/**
 * The blocks on the admin page: the list, blocking by hand and lifting.
 * Administrators only; every change needs a recent password confirmation
 * and is written to the audit log.
 *
 * @psalm-import-type IntrusionDetectionBan from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionBanList from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionError from ResponseDefinitions
 */
#[OpenAPI(scope: OpenAPI::SCOPE_ADMINISTRATION)]
class BanApiController extends AdminOCSController {
	public const MAX_PAGE = 100;

	public function __construct(
		IRequest $request,
		IL10N $l,
		ActorResolver $actors,
		private readonly ITimeFactory $timeFactory,
		private readonly BanMapper $banMapper,
		private readonly BanService $banService,
		private readonly BanPresenter $bans,
	) {
		parent::__construct($request, $l, $actors);
	}

	/**
	 * List blocks
	 *
	 * @param bool $all Also blocks that ended or were lifted, newest first; otherwise active blocks by expiry
	 * @param int<1, 100> $limit At most this many
	 * @param int<0, max> $offset Skip this many
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionBanList, array{}>
	 *
	 * 200: Blocks returned
	 */
	#[ApiRoute(verb: 'GET', url: '/api/v1/bans')]
	public function bans(bool $all = false, int $limit = 50, int $offset = 0): DataResponse {
		$limit = max(1, min(self::MAX_PAGE, $limit));
		$now = $this->timeFactory->getTime();
		$bans = $this->banMapper->findList($now, $all, $limit + 1, max(0, $offset));
		return new DataResponse([
			'bans' => $this->bans->presentAll(array_slice($bans, 0, $limit), $this->l),
			'hasMore' => count($bans) > $limit,
			'activeCount' => $this->banMapper->countActive($now),
		]);
	}

	/**
	 * Block an address or a network by hand
	 *
	 * Accepts an IPv4 address, an IPv4 /24 network, or an IPv6 address or
	 * /64 network (an IPv6 address is blocked with its /64). Your own
	 * address, the server and addresses on the brute-force allowlist cannot
	 * be blocked.
	 *
	 * @param string $target The address or network
	 * @param int<1, 3> $level Escalation level, which sets the duration
	 * @param int<300, 7776000>|null $duration A duration in seconds instead of the level's (5 minutes to 90 days)
	 * @param string $note Why the address is blocked
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionBan, array{}>|DataResponse<Http::STATUS_BAD_REQUEST, IntrusionDetectionError, array{}>
	 *
	 * 200: Address blocked
	 * 400: The address, level, duration or note is not valid
	 */
	#[ApiRoute(verb: 'POST', url: '/api/v1/bans')]
	#[PasswordConfirmationRequired]
	public function addBan(string $target, int $level = 1, ?int $duration = null, string $note = ''): DataResponse {
		return new DataResponse($this->bans->present($this->banService->banManually($target, $level, $this->actor(), $note, $duration), $this->l));
	}

	/**
	 * Lift a block
	 *
	 * @param int $id The block id
	 * @param string $note Why the block is lifted
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionBan, array{}>|DataResponse<Http::STATUS_BAD_REQUEST, IntrusionDetectionError, array{}>
	 * @throws OCSNotFoundException The block does not exist
	 *
	 * 200: Block lifted, or it was already lifted
	 * 400: The note is missing or too long
	 */
	#[ApiRoute(verb: 'DELETE', url: '/api/v1/bans/{id}', requirements: ['id' => '\d+'])]
	#[PasswordConfirmationRequired]
	public function liftBan(int $id, string $note = ''): DataResponse {
		if (trim($note) === '') {
			return $this->error($this->l->t('Please say why the block is lifted. The note is kept with the block and in the audit log.'), 'note', 'required');
		}
		$ban = $this->found(fn () => $this->banService->liftById($id, $this->actor(), $note), $this->l->t('This block does not exist (any more).'));
		return new DataResponse($this->bans->present($ban, $this->l));
	}

}
