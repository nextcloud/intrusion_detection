<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Controller;

use OCA\IntrusionDetection\Admin\DailyStats;
use OCA\IntrusionDetection\Admin\DetectionPresenter;
use OCA\IntrusionDetection\Admin\LookupService;
use OCA\IntrusionDetection\AdminChange\ActorResolver;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Definition\Severity;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\ApiRoute;
use OCP\AppFramework\Http\Attribute\OpenAPI;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\OCS\OCSNotFoundException;
use OCP\IL10N;
use OCP\IRequest;

/**
 * The detections on the admin page: the list, one detection explained,
 * the daily counts and the lookup of a reference, an address or an account.
 * Administrators only; nothing here changes anything.
 *
 * @psalm-import-type IntrusionDetectionDetectionList from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionDetectionDetail from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionDailyStats from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionLookup from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionError from ResponseDefinitions
 */
#[OpenAPI(scope: OpenAPI::SCOPE_ADMINISTRATION)]
class DetectionApiController extends AdminOCSController {
	public const MAX_PAGE = 100;

	public function __construct(
		IRequest $request,
		IL10N $l,
		ActorResolver $actors,
		private readonly DetectionMapper $detectionMapper,
		private readonly DetectionPresenter $detections,
		private readonly DailyStats $dailyStats,
		private readonly LookupService $lookupService,
	) {
		parent::__construct($request, $l, $actors);
	}

	/**
	 * List detections, newest first
	 *
	 * @param string $check Only these checks (comma-separated ids)
	 * @param string $severity Only these severities (comma-separated: low, medium, high, critical)
	 * @param string $user Only detections about this account
	 * @param string $address Only detections from this address
	 * @param ''|'enforced'|'observed' $mode Only detections Nextcloud acted on, or only observed ones
	 * @param int<0, max> $since Only detections since this Unix time
	 * @param int<1, 100> $limit At most this many
	 * @param int<0, max> $offset Skip this many
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionDetectionList, array{}>|DataResponse<Http::STATUS_BAD_REQUEST, IntrusionDetectionError, array{}>
	 *
	 * 200: Detections returned
	 * 400: A filter is not valid
	 */
	#[ApiRoute(verb: 'GET', url: '/api/v1/detections')]
	public function detections(
		string $check = '',
		string $severity = '',
		string $user = '',
		string $address = '',
		string $mode = '',
		int $since = 0,
		int $limit = 25,
		int $offset = 0,
	): DataResponse {
		$checkIds = self::splitList($check);
		foreach ($checkIds as $checkId) {
			if (!preg_match('/^[a-z][a-z0-9_]{2,31}$/', $checkId)) {
				return $this->badFilter('check');
			}
		}
		$severities = self::splitList($severity);
		foreach ($severities as $value) {
			if (Severity::tryFrom($value) === null) {
				return $this->badFilter('severity');
			}
		}
		$ip = null;
		if ($address !== '') {
			$source = SourceKey::tryFromIp($address);
			if ($source === null) {
				return $this->badFilter('address');
			}
			$ip = $source->ip;
		}
		if (!in_array($mode, ['', 'enforced', 'observed'], true)) {
			return $this->badFilter('mode');
		}
		if ($since < 0 || $limit < 1 || $limit > self::MAX_PAGE || $offset < 0) {
			return $this->badFilter($since < 0 ? 'since' : ($offset < 0 ? 'offset' : 'limit'));
		}
		$user = trim($user);
		$filter = new DetectionFilter(
			checkIds: $checkIds,
			severities: $severities,
			uid: $user === '' ? null : $user,
			ip: $ip,
			enforced: $mode === '' ? null : $mode === 'enforced',
			since: $since > 0 ? $since : null,
			// One more than asked for tells whether there are more, without counting them all.
			limit: $limit + 1,
			offset: $offset,
		);
		$found = $this->detectionMapper->findList($filter);
		return new DataResponse([
			'detections' => $this->detections->rows(array_slice($found, 0, $limit), $this->l),
			'hasMore' => count($found) > $limit,
		]);
	}

	/**
	 * Explain one detection
	 *
	 * The detection with its narrative ("Why did this happen?"), the
	 * attempts of its source while they are still kept (one hour), and the
	 * blocks that cover its address now.
	 *
	 * @param int $id The detection id
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionDetectionDetail, array{}>
	 * @throws OCSNotFoundException The detection does not exist
	 *
	 * 200: Detection returned
	 */
	#[ApiRoute(verb: 'GET', url: '/api/v1/detections/{id}', requirements: ['id' => '\d+'])]
	public function detection(int $id): DataResponse {
		$detection = $this->found(fn () => $this->detectionMapper->findById($id), $this->l->t('This detection does not exist (any more).'));
		return new DataResponse($this->detections->detail($detection, $this->l));
	}

	/**
	 * Detections per day, for the overview chart
	 *
	 * @param int<1, 90> $days How many days, ending today
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionDailyStats, array{}>
	 *
	 * 200: Counts returned
	 */
	#[ApiRoute(verb: 'GET', url: '/api/v1/stats/daily')]
	public function dailyStats(int $days = 30): DataResponse {
		return new DataResponse($this->dailyStats->days($days));
	}

	/**
	 * Look up a block reference, an address or an account
	 *
	 * A reference (like K7Q2-MPXA, in any case, with or without the dash)
	 * returns its block; an address returns the blocks covering it and its
	 * recent detections; an account returns the recent detections about it.
	 *
	 * @param string $q What to look up
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionLookup, array{}>
	 *
	 * 200: Result returned; kind "none" when nothing matched
	 */
	#[ApiRoute(verb: 'GET', url: '/api/v1/lookup')]
	public function lookup(string $q = ''): DataResponse {
		return new DataResponse($this->lookupService->lookup($q, $this->l));
	}

	/**
	 * @return list<string>
	 */
	private static function splitList(string $value): array {
		return array_values(array_filter(array_map('trim', explode(',', $value)), static fn (string $s): bool => $s !== ''));
	}

	/**
	 * @return DataResponse<Http::STATUS_BAD_REQUEST, IntrusionDetectionError, array{}>
	 */
	private function badFilter(string $param): DataResponse {
		return $this->error($this->l->t('The filter "%s" is not valid.', [$param]), $param, 'invalid_filter');
	}
}
