<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Controller;

use OCA\IntrusionDetection\Admin\TrapsOverview;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\Checks\TrapUrl;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Decoy\DecoyFormat;
use OCA\IntrusionDetection\Decoy\DecoyService;
use OCA\IntrusionDetection\Definition\InvalidParamException;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCA\IntrusionDetection\Traps\ReservedNames;
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\ApiRoute;
use OCP\AppFramework\Http\Attribute\OpenAPI;
use OCP\AppFramework\Http\Attribute\PasswordConfirmationRequired;
use OCP\AppFramework\Http\Attribute\UserRateLimit;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\OCS\OCSNotFoundException;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IUserSession;

/**
 * The Decoys tab: decoy credentials, reserved names and trap paths.
 * Administrators only; every change needs a recent password confirmation
 * and is audited.
 *
 * The secret of a decoy is returned once, by the request that creates it,
 * and never stored: no endpoint can return it again.
 *
 * @psalm-import-type IntrusionDetectionTraps from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionNewDecoy from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionReservedNames from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionTrapPaths from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionError from ResponseDefinitions
 */
#[OpenAPI(scope: OpenAPI::SCOPE_ADMINISTRATION)]
class DecoyApiController extends AdminOCSController {
	public const MAX_CHANGES = 100;

	public function __construct(
		IRequest $request,
		IL10N $l,
		IUserSession $userSession,
		private readonly TrapsOverview $overview,
		private readonly DecoyService $decoys,
		private readonly ReservedNames $reservedNames,
		private readonly Settings $settings,
		private readonly AuditLogger $audit,
	) {
		parent::__construct($request, $l, $userSession);
	}

	/**
	 * List the decoys, reserved names and trap paths
	 *
	 * Decoys come without their secret, which is shown only once.
	 *
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionTraps, array{}>
	 *
	 * 200: Traps returned
	 */
	#[ApiRoute(verb: 'GET', url: '/api/v1/decoys')]
	public function index(): DataResponse {
		return new DataResponse($this->overview->get($this->l));
	}

	/**
	 * Create a decoy credential
	 *
	 * The answer contains the secret. It is not stored and cannot be shown
	 * again, so copy it right away.
	 *
	 * @param string $label Where the decoy will be planted, e.g. "old backup script on nas01"
	 * @param string $loginName An optional login name that no account uses; a login attempt with it is a trap of its own
	 * @param 'app-password'|'token' $secretFormat What the secret looks like; not called "format", which chooses the OCS response format
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionNewDecoy, array{}>|DataResponse<Http::STATUS_BAD_REQUEST, IntrusionDetectionError, array{}>
	 *
	 * 200: Decoy created; the secret is in the answer
	 * 400: The label, login name or format is not valid
	 */
	#[ApiRoute(verb: 'POST', url: '/api/v1/decoys')]
	#[PasswordConfirmationRequired]
	#[UserRateLimit(limit: 20, period: 600)]
	public function create(string $label, string $loginName = '', string $secretFormat = 'app-password'): DataResponse {
		$decoyFormat = DecoyFormat::tryFrom($secretFormat);
		if ($decoyFormat === null) {
			return $this->error($this->l->t('Choose what the secret looks like: an app password or a token.'), 'secretFormat', 'invalid_format');
		}
		try {
			[$decoy, $secret] = $this->decoys->create($label, $loginName === '' ? null : $loginName, $decoyFormat, $this->actor());
		} catch (InvalidParamException $e) {
			return $this->invalid($e);
		}
		$response = new DataResponse(['decoy' => TrapsOverview::decoy($decoy), 'secret' => $secret]);
		$response->addHeader('Cache-Control', 'no-store');
		return $response;
	}

	/**
	 * Delete a decoy credential
	 *
	 * Anyone who uses it afterwards is treated like any other failed login.
	 *
	 * @param int $id The decoy
	 * @return DataResponse<Http::STATUS_OK, array{deleted: int}, array{}>
	 * @throws OCSNotFoundException The decoy does not exist
	 *
	 * 200: Decoy deleted
	 */
	#[ApiRoute(verb: 'DELETE', url: '/api/v1/decoys/{id}', requirements: ['id' => '\d+'])]
	#[PasswordConfirmationRequired]
	public function delete(int $id): DataResponse {
		try {
			$this->decoys->delete($id, $this->actor());
		} catch (DoesNotExistException) {
			throw new OCSNotFoundException($this->l->t('This decoy does not exist (any more).'));
		}
		return new DataResponse(['deleted' => $id]);
	}

	/**
	 * Reserve login names, or release them
	 *
	 * Names of existing accounts cannot be reserved.
	 *
	 * @param list<string> $add Names to reserve
	 * @param list<string> $remove Names to release
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionReservedNames, array{}>|DataResponse<Http::STATUS_BAD_REQUEST, IntrusionDetectionError, array{}>
	 *
	 * 200: Reserved names changed
	 * 400: A name is not valid or belongs to an account
	 */
	#[ApiRoute(verb: 'PUT', url: '/api/v1/reserved-names')]
	#[PasswordConfirmationRequired]
	public function updateReservedNames(array $add = [], array $remove = []): DataResponse {
		$add = self::strings($add);
		$remove = self::strings($remove);
		if (count($add) + count($remove) > self::MAX_CHANGES) {
			return $this->error($this->l->t('Change at most %s names at once.', [(string)self::MAX_CHANGES]), 'names', 'too_many_items');
		}
		try {
			if ($add !== [] || $remove !== []) {
				$this->reservedNames->change($add, $remove, $this->actor());
			}
		} catch (InvalidParamException $e) {
			return $this->invalid($e);
		}
		return new DataResponse($this->overview->reservedNames());
	}

	/**
	 * Change the trap paths
	 *
	 * Add or remove your own paths (exact, or a prefix when they end with
	 * "*"), and switch the built-in list and the Exchange autodiscover path.
	 * Paths Nextcloud uses itself are refused.
	 *
	 * @param list<string> $add Paths to add
	 * @param list<string> $remove Paths to remove
	 * @param bool|null $builtinEnabled Use the built-in list
	 * @param bool|null $autodiscover Also trap the Exchange autodiscover path
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionTrapPaths, array{}>|DataResponse<Http::STATUS_BAD_REQUEST, IntrusionDetectionError, array{}>
	 *
	 * 200: Trap paths changed
	 * 400: A path is not valid or used by Nextcloud
	 */
	#[ApiRoute(verb: 'PUT', url: '/api/v1/trap-paths')]
	#[PasswordConfirmationRequired]
	public function updateTrapPaths(array $add = [], array $remove = [], ?bool $builtinEnabled = null, ?bool $autodiscover = null): DataResponse {
		$add = array_map('strtolower', self::strings($add));
		$remove = array_map('strtolower', self::strings($remove));
		if (count($add) + count($remove) > self::MAX_CHANGES) {
			return $this->error($this->l->t('Change at most %s paths at once.', [(string)self::MAX_CHANGES]), 'paths', 'too_many_items');
		}
		$paths = array_values(array_filter(
			array_merge($this->settings->paramList(TrapUrl::ID, 'paths'), $add),
			static fn (string $p): bool => !in_array($p, $remove, true),
		));
		$params = [];
		if ($add !== [] || $remove !== []) {
			$params['paths'] = $paths;
		}
		if ($builtinEnabled !== null) {
			$params['builtin_enabled'] = $builtinEnabled;
		}
		if ($autodiscover !== null) {
			$params['autodiscover'] = $autodiscover;
		}
		try {
			$changes = $this->settings->updateCheck(TrapUrl::ID, null, $params, null);
		} catch (InvalidParamException $e) {
			return $this->invalid($e);
		}
		if ($changes === []) {
			return new DataResponse($this->overview->trapPaths($this->l));
		}
		$this->audit->log('trap paths changed by %s: added %s, removed %s, built-in list %s, autodiscover %s', [
			'actor' => $this->actor(),
			'added' => implode(', ', $add),
			'removed' => implode(', ', $remove),
			'builtin' => $builtinEnabled === null ? 'unchanged' : ($builtinEnabled ? 'on' : 'off'),
			'autodiscover' => $autodiscover === null ? 'unchanged' : ($autodiscover ? 'on' : 'off'),
		]);
		return new DataResponse($this->overview->trapPaths($this->l));
	}

	/**
	 * @return list<string>
	 */
	private static function strings(array $values): array {
		$strings = [];
		foreach ($values as $value) {
			if (is_string($value) && trim($value) !== '') {
				$strings[] = trim($value);
			}
		}
		return $strings;
	}
}
