<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Controller;

use OCA\IntrusionDetection\Admin\BanPresenter;
use OCA\IntrusionDetection\Admin\CheckList;
use OCA\IntrusionDetection\Admin\DailyStats;
use OCA\IntrusionDetection\Admin\DetectionPresenter;
use OCA\IntrusionDetection\Admin\GlobalSettingsPresenter;
use OCA\IntrusionDetection\Admin\LookupService;
use OCA\IntrusionDetection\Admin\SettingsTransfer;
use OCA\IntrusionDetection\Admin\StatusService;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\CheckDefinition;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\InvalidParamException;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Check\ParamDefinition;
use OCA\IntrusionDetection\Check\Requirement;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Check\Severity;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Learning\LearningService;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\BanRefusedException;
use OCA\IntrusionDetection\Response\BanService;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\ApiRoute;
use OCP\AppFramework\Http\Attribute\OpenAPI;
use OCP\AppFramework\Http\Attribute\PasswordConfirmationRequired;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\OCS\OCSNotFoundException;
use OCP\AppFramework\OCSController;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IUserSession;

/**
 * The admin page's API. Administrators only (there is no delegation: this
 * page can turn protection off and lift blocks). Every change needs a recent
 * password confirmation and is written to the audit log.
 *
 * @psalm-import-type IntrusionDetectionStatus from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionCheck from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionCheckList from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionDetectionList from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionDetectionDetail from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionDailyStats from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionBan from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionBanList from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionLookup from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionLearning from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionSettings from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionExport from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionError from ResponseDefinitions
 */
#[OpenAPI(scope: OpenAPI::SCOPE_ADMINISTRATION)]
class AdminApiController extends OCSController {
	public const MAX_PAGE = 100;
	public const MAX_NOTE = 255;
	public const MIN_BAN_DURATION = 300;
	public const MAX_BAN_DURATION = BanService::MAX_DURATION;

	public function __construct(
		string $appName,
		IRequest $request,
		private readonly IL10N $l,
		private readonly IUserSession $userSession,
		private readonly ITimeFactory $timeFactory,
		private readonly CheckRegistry $registry,
		private readonly Settings $settings,
		private readonly StatusService $status,
		private readonly CheckList $checks,
		private readonly DetectionMapper $detectionMapper,
		private readonly DetectionPresenter $detections,
		private readonly DailyStats $dailyStats,
		private readonly BanMapper $banMapper,
		private readonly BanService $banService,
		private readonly BanPresenter $bans,
		private readonly LookupService $lookupService,
		private readonly LearningService $learningService,
		private readonly GlobalSettingsPresenter $globalSettings,
		private readonly GlobalSettings $globals,
		private readonly SettingsTransfer $transfer,
		private readonly RemoteAddressResolver $addresses,
		private readonly AuditLogger $audit,
	) {
		parent::__construct($appName, $request);
	}

	/**
	 * What intrusion detection is doing right now
	 *
	 * The state (protecting, learning or off), the last 24 hours in numbers,
	 * the prerequisites, the measured cost of the address check and the
	 * problems to show under the status banner.
	 *
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionStatus, array{}>
	 *
	 * 200: Status returned
	 */
	#[ApiRoute(verb: 'GET', url: '/api/v1/status')]
	public function status(): DataResponse {
		return new DataResponse($this->status->status($this->l));
	}

	/**
	 * List the configurable checks
	 *
	 * Every check with its explanation texts (the "How it decides" template
	 * and the filled sentence), its settings, responses, cost, requirements,
	 * effective mode, and what it did in the last 7 days.
	 *
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionCheckList, array{}>
	 *
	 * 200: Checks returned
	 */
	#[ApiRoute(verb: 'GET', url: '/api/v1/checks')]
	public function checks(): DataResponse {
		return new DataResponse($this->checks->all($this->l));
	}

	/**
	 * Change the mode, responses or settings of a check
	 *
	 * Every given value is validated with the same rules as occ before
	 * anything is saved.
	 *
	 * @param string $id The check id
	 * @param 'off'|'observe'|'protect'|null $mode The new mode
	 * @param list<string>|null $responses The responses to run, from the check's allowed responses
	 * @param array<string, mixed>|null $params New values of the check's settings, by name; durations in seconds or as text like "10m"
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionCheck, array{}>|DataResponse<Http::STATUS_BAD_REQUEST, IntrusionDetectionError, array{}>
	 * @throws OCSNotFoundException The check does not exist
	 *
	 * 200: Check changed
	 * 400: A value is not valid; nothing was saved
	 */
	#[ApiRoute(verb: 'PUT', url: '/api/v1/checks/{id}', requirements: ['id' => '[a-z][a-z0-9_]{2,31}'])]
	#[PasswordConfirmationRequired]
	public function updateCheck(string $id, ?string $mode = null, ?array $responses = null, ?array $params = null): DataResponse {
		$check = $this->configurableCheck($id);
		try {
			$newMode = null;
			if ($mode !== null) {
				$newMode = Mode::tryFrom($mode) ?? throw new InvalidParamException('unknown_mode');
			}
			$newResponses = null;
			if ($responses !== null) {
				$newResponses = [];
				foreach ($responses as $value) {
					$newResponses[] = self::allowedResponse($check, $value);
				}
			}
			$newParams = [];
			foreach ($params ?? [] as $name => $value) {
				$newParams[(string)$name] = self::validated($check->param((string)$name), $value);
			}
			$changes = $this->settings->updateCheck($id, $newMode, $newParams, $newResponses);
		} catch (InvalidParamException $e) {
			return $this->invalid($e);
		}

		if ($changes !== []) {
			$this->audit->log('check %s changed by %s: %s', [
				'check' => $id,
				'actor' => $this->actor(),
				'change' => json_encode($changes),
			]);
		}
		return new DataResponse($this->checks->one($check, $this->l));
	}

	/**
	 * Put a check back to its default mode, responses and settings
	 *
	 * @param string $id The check id
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionCheck, array{}>
	 * @throws OCSNotFoundException The check does not exist
	 *
	 * 200: Check reset
	 */
	#[ApiRoute(verb: 'POST', url: '/api/v1/checks/{id}/reset', requirements: ['id' => '[a-z][a-z0-9_]{2,31}'])]
	#[PasswordConfirmationRequired]
	public function resetCheck(string $id): DataResponse {
		$check = $this->configurableCheck($id);
		$this->settings->resetCheck($id);
		$this->audit->log('check %s reset to defaults by %s', ['check' => $id, 'actor' => $this->actor()]);
		return new DataResponse($this->checks->one($check, $this->l));
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
			limit: $limit,
			offset: $offset,
		);
		return new DataResponse([
			'detections' => $this->detections->rows($this->detectionMapper->findList($filter), $this->l),
			'total' => $this->detectionMapper->count($filter),
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
		try {
			$detection = $this->detectionMapper->findById($id);
		} catch (DoesNotExistException) {
			throw new OCSNotFoundException($this->l->t('This detection does not exist (any more).'));
		}
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
		$target = trim($target);
		$note = trim($note);
		if ($level < 1 || $level > 3) {
			return $this->error($this->l->t('The level must be 1, 2 or 3.'), 'level', 'invalid_level');
		}
		if ($duration !== null && ($duration < self::MIN_BAN_DURATION || $duration > self::MAX_BAN_DURATION)) {
			return $this->error($this->l->t('A block lasts from 5 minutes to 90 days.'), 'duration', 'invalid_duration');
		}
		if (mb_strlen($note) > self::MAX_NOTE) {
			return $this->error($this->l->t('The note can have at most %s characters.', [(string)self::MAX_NOTE]), 'note', 'too_long');
		}
		$refusal = $this->refuseTarget($target);
		if ($refusal !== null) {
			return $this->error($refusal, 'target', 'invalid_target');
		}
		try {
			$ban = $this->banService->banManually($target, $level, $this->actor(), $note === '' ? null : $note, $duration);
		} catch (BanRefusedException $e) {
			return $this->error($this->l->t('%s contains this server, a loopback address or an address on the brute-force allowlist, so it is never blocked.', [$e->cidr]), 'target', 'invalid_target');
		} catch (\InvalidArgumentException) {
			return $this->error($this->targetHelp(), 'target', 'invalid_target');
		}
		$this->audit->log('block %s (%s) added by %s: %s', [
			'reference' => $ban->getDisplayReference(),
			'cidr' => $ban->getCidr(),
			'actor' => $this->actor(),
			'note' => $note,
		]);
		return new DataResponse($this->bans->present($ban, $this->l));
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
		$note = trim($note);
		if ($note === '') {
			return $this->error($this->l->t('Please say why the block is lifted. The note is kept with the block and in the audit log.'), 'note', 'required');
		}
		if (mb_strlen($note) > self::MAX_NOTE) {
			return $this->error($this->l->t('The note can have at most %s characters.', [(string)self::MAX_NOTE]), 'note', 'too_long');
		}
		try {
			$ban = $this->banMapper->findById($id);
		} catch (DoesNotExistException) {
			throw new OCSNotFoundException($this->l->t('This block does not exist (any more).'));
		}
		if ($ban->getLiftedAt() === null) {
			$this->banService->lift($ban, $this->actor(), $note);
			$this->audit->log('block %s (%s) lifted by %s: %s', [
				'reference' => $ban->getDisplayReference(),
				'cidr' => $ban->getCidr(),
				'actor' => $this->actor(),
				'note' => $note,
			]);
		}
		return new DataResponse($this->bans->present($ban, $this->l));
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
	 * 400: The action or the number of days is not valid
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
		try {
			$parsed = [];
			foreach ($values as $name => $value) {
				$name = (string)$name;
				$definition = $this->globals->get($name);
				if ($definition === null || !$this->globalSettings->isEditable($name)) {
					throw new InvalidParamException('unknown_param', ['param' => $name]);
				}
				$parsed[$name] = self::validated($definition, $value);
			}
			$changes = $this->settings->updateGlobals($parsed);
		} catch (InvalidParamException $e) {
			return $this->invalid($e);
		}
		if (array_key_exists(GlobalSettings::ENABLED, $changes)) {
			$this->audit->log('intrusion detection turned %s by %s', [
				'state' => $changes[GlobalSettings::ENABLED] === true ? 'on' : 'off',
				'actor' => $this->actor(),
			]);
		}
		if ($changes !== []) {
			$this->audit->log('settings changed by %s: %s', ['actor' => $this->actor(), 'change' => json_encode($changes)]);
		}
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
		$this->transfer->resetAll();
		$this->audit->log('all settings reset to defaults by %s', ['actor' => $this->actor()]);
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

	/**
	 * @throws OCSNotFoundException
	 */
	private function configurableCheck(string $id): CheckDefinition {
		if (!$this->registry->has($id) || $this->registry->get($id)->internal) {
			throw new OCSNotFoundException($this->l->t('There is no check "%s".', [$id]));
		}
		return $this->registry->get($id);
	}

	/**
	 * A value from the page: text as typed into a field is parsed (so "10m"
	 * works for durations), anything else is validated as it is.
	 *
	 * @return int|float|bool|string|list<string>
	 * @throws InvalidParamException
	 */
	private static function validated(ParamDefinition $definition, mixed $value): int|float|bool|string|array {
		return is_string($value) ? $definition->parse($value) : $definition->validate($value);
	}

	/**
	 * @throws InvalidParamException
	 */
	private static function allowedResponse(CheckDefinition $check, mixed $value): ResponseType {
		$response = is_string($value) ? ResponseType::tryFrom($value) : null;
		if ($response === null || !$check->allowsResponse($response)) {
			throw new InvalidParamException('unknown_response', ['response' => is_scalar($value) ? (string)$value : '']);
		}
		return $response;
	}

	/**
	 * Why a manual block of this target is refused, or null when it is allowed.
	 */
	private function refuseTarget(string $target): ?string {
		$parts = explode('/', $target, 2);
		$source = SourceKey::tryFromIp($parts[0]);
		if ($source === null || (isset($parts[1]) && !ctype_digit($parts[1]))) {
			return $this->targetHelp();
		}
		$wholeNetwork = $source->family === 6 || ($parts[1] ?? '') === '24';
		if ($this->addresses->isNeverBlocked($source)) {
			return $this->l->t('%s is this server or a loopback address. It is never blocked.', [$source->ip]);
		}
		if ($this->addresses->isBypassListed($source)) {
			return $this->l->t('%s is on the brute-force allowlist, so it is never blocked. Remove it from the allowlist first.', [$source->ip]);
		}
		$own = $this->addresses->current();
		if ($own !== null && ($wholeNetwork ? $own->sameNetwork($source) : $own->ipKey === $source->ipKey)) {
			return $this->l->t('This would block your own address (%s) and lock you out. If you really need it, use occ intrusion:bans:add.', [$own->ip]);
		}
		return null;
	}

	private function targetHelp(): string {
		return $this->l->t('Enter an IPv4 address, an IPv4 network ending in /24, or an IPv6 address or /64 network.');
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
	private function invalid(InvalidParamException $e): DataResponse {
		$message = $e->describe($this->l);
		if ($e->reason === 'mode_unavailable') {
			$requirement = Requirement::tryFrom((string)($e->details['why'] ?? ''));
			if ($requirement !== null) {
				$message = $this->l->t('This check cannot run on this server: %s', [$requirement->describe($this->l)]);
			}
		}
		$param = $e->details['param'] ?? null;
		return $this->error($message, $param === null ? null : (string)$param, $e->reason);
	}

	/**
	 * @return DataResponse<Http::STATUS_BAD_REQUEST, IntrusionDetectionError, array{}>
	 */
	private function badFilter(string $param): DataResponse {
		return $this->error($this->l->t('The filter "%s" is not valid.', [$param]), $param, 'invalid_filter');
	}

	/**
	 * @return DataResponse<Http::STATUS_BAD_REQUEST, IntrusionDetectionError, array{}>
	 */
	private function error(string $message, ?string $param, string $reason): DataResponse {
		return new DataResponse(['message' => $message, 'param' => $param, 'reason' => $reason], Http::STATUS_BAD_REQUEST);
	}

	private function actor(): string {
		return $this->userSession->getUser()?->getUID() ?? 'unknown';
	}
}
