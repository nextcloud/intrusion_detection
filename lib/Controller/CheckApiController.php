<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Controller;

use OCA\IntrusionDetection\Admin\CheckList;
use OCA\IntrusionDetection\Admin\StatusService;
use OCA\IntrusionDetection\AdminChange\ActorResolver;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Configure\ProtectionLevels;
use OCA\IntrusionDetection\Configure\SettingsEditor;
use OCA\IntrusionDetection\Definition\CheckDefinition;
use OCA\IntrusionDetection\Definition\InvalidParamException;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\ParamDefinition;
use OCA\IntrusionDetection\Definition\ProtectionLevel;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\ApiRoute;
use OCP\AppFramework\Http\Attribute\OpenAPI;
use OCP\AppFramework\Http\Attribute\PasswordConfirmationRequired;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\OCS\OCSNotFoundException;
use OCP\IL10N;
use OCP\IRequest;

/**
 * The checks on the admin page: the status on top, the check cards and
 * the protection level. Administrators only; every change needs a recent
 * password confirmation and is written to the audit log.
 *
 * @psalm-import-type IntrusionDetectionStatus from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionCheck from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionCheckList from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionProtectionLevel from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionProtectionLevelChange from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionError from ResponseDefinitions
 */
#[OpenAPI(scope: OpenAPI::SCOPE_ADMINISTRATION)]
class CheckApiController extends AdminOCSController {
	public function __construct(
		IRequest $request,
		IL10N $l,
		ActorResolver $actors,
		private readonly CheckRegistry $registry,
		private readonly SettingsEditor $settings,
		private readonly StatusService $status,
		private readonly CheckList $checks,
		private readonly ProtectionLevels $protectionLevels,
		private readonly AuditLogger $audit,
	) {
		parent::__construct($request, $l, $actors);
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
	 * Show the protection level
	 *
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionProtectionLevel, array{}>
	 *
	 * 200: Protection level returned; "custom" when a limit was changed by hand
	 */
	#[ApiRoute(verb: 'GET', url: '/api/v1/protection-level')]
	public function protectionLevel(): DataResponse {
		return new DataResponse(['level' => $this->settings->protectionLevel()->value]);
	}

	/**
	 * Set the protection level
	 *
	 * Sets the count limits of every check and the block durations to the
	 * level in one go: recommended are the defaults, strict halves the
	 * limits and doubles the block durations, relaxed does the opposite,
	 * always within each setting's range. Modes and responses stay as they are.
	 *
	 * @param 'recommended'|'strict'|'relaxed' $level The level
	 * @return DataResponse<Http::STATUS_OK, IntrusionDetectionProtectionLevelChange, array{}>|DataResponse<Http::STATUS_BAD_REQUEST, IntrusionDetectionError, array{}>
	 *
	 * 200: Protection level set
	 * 400: The level is not valid; nothing was changed
	 */
	#[ApiRoute(verb: 'PUT', url: '/api/v1/protection-level')]
	#[PasswordConfirmationRequired]
	public function updateProtectionLevel(string $level): DataResponse {
		$chosen = ProtectionLevel::tryFrom($level);
		if ($chosen === null || !in_array($chosen, ProtectionLevel::choosable(), true)) {
			return $this->error($this->l->t('Choose the recommended, strict or relaxed protection level.'), 'level', 'invalid_level');
		}
		$changes = $this->protectionLevels->apply($chosen);
		$this->audit->log('protection level set to %s by %s: %s', [
			'level' => $chosen->value,
			'actor' => $this->actor(),
			'change' => json_encode($changes),
		]);
		return new DataResponse([
			'level' => $this->settings->protectionLevel()->value,
			'checks' => $this->checks->all($this->l),
		]);
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
}
