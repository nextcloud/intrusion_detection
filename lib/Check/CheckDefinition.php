<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check;

use OCP\IL10N;

/**
 * Everything the app knows about one check, apart from how it detects.
 *
 * The registry of these definitions is the single source of truth for the
 * config lexicon, validation in the admin API and occ, the admin page and the
 * explanation texts.
 */
final class CheckDefinition {
	/** @var array<string, ParamDefinition> */
	private array $paramsByName = [];

	/**
	 * @param list<ParamDefinition> $params
	 * @param list<ResponseType> $responses the responses an admin can choose for this check
	 * @param list<ResponseType> $defaultResponses
	 * @param list<DataKind> $stores
	 * @param list<Requirement> $requirements
	 * @param \Closure(IL10N): CheckTexts $texts
	 */
	public function __construct(
		public readonly string $id,
		public readonly Category $category,
		public readonly Mode $defaultMode,
		public readonly Severity $severity,
		public readonly array $params,
		public readonly array $responses,
		public readonly array $defaultResponses,
		public readonly CostClass $cost,
		public readonly array $stores,
		private readonly \Closure $texts,
		public readonly bool $sendsData = false,
		public readonly array $requirements = [],
		public readonly bool $internal = false,
		public readonly bool $actsWhileLearning = false,
		public readonly bool $simulatable = false,
	) {
		if (!preg_match('/^[a-z][a-z0-9_]{2,31}$/', $id)) {
			throw new \InvalidArgumentException('Invalid check id: ' . $id);
		}
		foreach ($params as $param) {
			if (isset($this->paramsByName[$param->name])) {
				throw new \InvalidArgumentException('Duplicate parameter ' . $param->name . ' in ' . $id);
			}
			$this->paramsByName[$param->name] = $param;
		}
		foreach ($defaultResponses as $response) {
			if (!in_array($response, $responses, true)) {
				throw new \InvalidArgumentException('Default response ' . $response->value . ' of ' . $id . ' is not an allowed response');
			}
		}
	}

	public function param(string $name): ParamDefinition {
		return $this->paramsByName[$name] ?? throw new InvalidParamException('unknown_param', ['param' => $name]);
	}

	public function hasParam(string $name): bool {
		return isset($this->paramsByName[$name]);
	}

	public function allowsResponse(ResponseType $response): bool {
		return in_array($response, $this->responses, true);
	}

	public function texts(IL10N $l): CheckTexts {
		return ($this->texts)($l);
	}
}
