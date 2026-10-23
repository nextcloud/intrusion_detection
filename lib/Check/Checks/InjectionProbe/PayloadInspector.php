<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\InjectionProbe;

/**
 * Inspects a whole request: the path, each query parameter and each form
 * field, within the byte budget, skipping parameters that are never
 * inspected. The request body is never read beyond what PHP already parsed
 * into the form fields.
 */
class PayloadInspector {
	/** At most this many query parameters and form fields are looked at */
	public const MAX_FIELDS = 1000;
	public const MAX_NAME_LENGTH = 100;

	/**
	 * Path segments after these hold share, calendar, login flow, call,
	 * conversation, password reset or lock link tokens; in an excerpt a
	 * token-like segment there is replaced by asterisks.
	 */
	private const TOKEN_SEGMENTS = '~(/(?:s|p|publicpreview|public-files|public-calendars|flow|public|call|room|share|token|form|lock/\d+)/)([a-z0-9_.+-]{1,64})(?=/|$)~';

	public function __construct(
		private readonly PayloadMatcher $matcher,
	) {
	}

	/**
	 * The strongest matching part of the request, or null when nothing matched.
	 */
	public function inspect(RequestParts $parts, PayloadRules $rules): ?PayloadHit {
		$best = null;
		$bestForm = null;
		$others = [];
		foreach ($this->values($parts, $rules) as $value) {
			if ($value->raw === null) {
				continue;
			}
			$analysis = $this->matcher->analyse($value->raw, $rules, $value->location === PayloadHit::LOCATION_PATH);
			if (!$analysis->fires()) {
				continue;
			}
			$form = $analysis->strongest();
			if ($bestForm === null || $form->weight > $bestForm->weight) {
				if ($best !== null) {
					$others[] = $best->name;
				}
				$best = $value;
				$bestForm = $form;
			} else {
				$others[] = $value->name;
			}
		}
		if ($best === null || $bestForm === null) {
			return null;
		}
		$excerptFrom = $best->location === PayloadHit::LOCATION_PATH ? self::maskTokens($bestForm) : $bestForm;
		return new PayloadHit(
			$best->location,
			$best->name,
			$bestForm->matches,
			$bestForm->weight,
			$rules->minWeight,
			$bestForm->encoding,
			$best->location === PayloadHit::LOCATION_PATH || PayloadRules::quotesValue($best->name) ? PayloadMatcher::excerpt($excerptFrom) : '',
			array_slice(array_values(array_unique(array_filter($others, static fn (string $n): bool => $n !== ''))), 0, PayloadHit::MAX_OTHERS),
		);
	}

	/**
	 * Every part of the request in the order it is inspected: path, query
	 * string, form fields. Once the byte budget is spent, the rest is skipped.
	 *
	 * @return list<InspectedValue>
	 */
	public function values(RequestParts $parts, PayloadRules $rules): array {
		$values = [];
		$budget = $rules->maxBytes;
		if ($parts->path !== '') {
			$values[] = self::cut(PayloadHit::LOCATION_PATH, '', $parts->path, $budget);
		}
		$fields = 0;
		if ($parts->query !== '') {
			$query = substr($parts->query, 0, PreFilter::MAX_SCAN);
			foreach (explode('&', $query, self::MAX_FIELDS + 1) as $pair) {
				if ($pair === '' || ++$fields > self::MAX_FIELDS) {
					continue;
				}
				$equals = strpos($pair, '=');
				$name = self::cleanName(urldecode($equals === false ? $pair : substr($pair, 0, $equals)));
				$raw = $equals === false ? '' : substr($pair, $equals + 1);
				$values[] = self::field(PayloadHit::LOCATION_QUERY, $name, $raw, $rules, $parts->isSearchRoute(), $budget);
			}
		}
		foreach (self::flatten($parts->post) as $name => $raw) {
			if (++$fields > self::MAX_FIELDS) {
				break;
			}
			$values[] = self::field(PayloadHit::LOCATION_FORM, self::cleanName($name), $raw, $rules, $parts->isSearchRoute(), $budget);
		}
		return $values;
	}

	private static function field(string $location, string $name, string $raw, PayloadRules $rules, bool $searchRoute, int &$budget): InspectedValue {
		$excluded = $rules->exclusion($name, $searchRoute);
		if ($excluded !== null) {
			return new InspectedValue($location, $name, null, $excluded);
		}
		return self::cut($location, $name, $raw, $budget);
	}

	/**
	 * @param PayloadHit::LOCATION_* $location
	 */
	private static function cut(string $location, string $name, string $raw, int &$budget): InspectedValue {
		if ($budget <= 0) {
			return new InspectedValue($location, $name, null, InspectedValue::SKIPPED_BUDGET);
		}
		$truncated = strlen($raw) > $budget;
		$value = $truncated ? substr($raw, 0, $budget) : $raw;
		$budget -= strlen($value);
		return new InspectedValue($location, $name, $value, null, $truncated);
	}

	/**
	 * Form fields as name => value, nested arrays as `a[b]`, at most four levels deep.
	 *
	 * @param array<array-key, mixed> $fields
	 * @return \Generator<string, string>
	 */
	private static function flatten(array $fields, string $prefix = '', int $depth = 0): \Generator {
		foreach ($fields as $key => $value) {
			$name = $prefix === '' ? (string)$key : $prefix . '[' . $key . ']';
			if (is_string($value)) {
				yield $name => $value;
			} elseif (is_array($value) && $depth < 4) {
				yield from self::flatten($value, $name, $depth + 1);
			}
		}
	}

	private static function cleanName(string $name): string {
		$clean = preg_replace('~[\x00-\x1f\x7f]~', '', mb_scrub($name, 'UTF-8')) ?? '';
		return mb_substr($clean, 0, self::MAX_NAME_LENGTH);
	}

	/**
	 * The same text with token-like path segments replaced by as many
	 * asterisks, so the match offset stays right.
	 */
	private static function maskTokens(FormMatch $form): FormMatch {
		$masked = preg_replace_callback(self::TOKEN_SEGMENTS, static fn (array $m): string => $m[1] . str_repeat('*', strlen($m[2])), $form->text);
		return $masked === null ? $form : new FormMatch($form->encoding, $masked, $form->matches, $form->weight, $form->offset);
	}
}
