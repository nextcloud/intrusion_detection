<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Payload;

use OCP\IL10N;

/**
 * "Test a URL": runs the injection probe check's matcher on a URL or a
 * single value and shows every step, without sending a request and without
 * recording anything. Used by occ intrusion:payload:test and the admin API.
 */
class PayloadTester {
	/** Longer input is cut */
	public const MAX_INPUT = 65536;
	/** Texts in the result are cut to this many characters */
	public const MAX_SHOWN = 1000;

	public function __construct(
		private readonly PayloadSettings $settings,
		private readonly PayloadInspector $inspector,
		private readonly PayloadMatcher $matcher,
	) {
	}

	/**
	 * @param string $input a URL (absolute, or a path starting with /) or one parameter value
	 * @return array{
	 *     kind: 'url'|'value',
	 *     prefilter: bool,
	 *     pathExcluded: bool,
	 *     minWeight: int,
	 *     maxBytes: int,
	 *     signaturesVersion: int,
	 *     fires: bool,
	 *     modes: array{anonymous: string, authenticated: string},
	 *     values: list<array<string, mixed>>,
	 * }
	 */
	public function test(string $input, IL10N $l): array {
		$input = substr(trim($input), 0, self::MAX_INPUT);
		$rules = $this->settings->rules();
		$isUrl = str_starts_with($input, '/') || preg_match('~^https?://~i', $input) === 1;
		if ($isUrl) {
			$uri = preg_replace('~^https?://[^/?#]*~i', '', $input) ?? $input;
			$parts = RequestParts::fromUri($uri === '' ? '/' : $uri, null);
			$values = $this->inspector->values($parts, $rules);
		} else {
			$parts = new RequestParts('', '', ['value' => $input], false);
			$values = [new InspectedValue(PayloadHit::LOCATION_FORM, '', substr($input, 0, $rules->maxBytes), null, strlen($input) > $rules->maxBytes)];
		}

		$fires = false;
		$shown = [];
		foreach ($values as $value) {
			$entry = [
				'location' => $value->location,
				'name' => $value->name,
				'skipped' => $value->skipped,
				'truncated' => $value->truncated,
			];
			if ($value->raw !== null) {
				$analysis = $this->matcher->analyse($value->raw, $rules, $value->location === PayloadHit::LOCATION_PATH);
				$fires = $fires || $analysis->fires();
				$entry += [
					'normalised' => self::shown($analysis->normalised()),
					'decoded' => array_map(self::shown(...), $analysis->decoded),
					'forms' => array_map(fn (FormMatch $form): array => [
						'encoding' => $form->encoding,
						'text' => self::shown($form->text),
						'weight' => $form->weight,
						'matches' => array_map(static fn (string $id, int $weight): array => [
							'id' => $id,
							'weight' => $weight,
							'description' => Signatures::describe($id, $l),
						], array_keys($form->matches), array_values($form->matches)),
					], $analysis->forms),
					'weight' => $analysis->strongest()->weight,
					'fires' => $analysis->fires(),
				];
			}
			$shown[] = $entry;
		}

		return [
			'kind' => $isUrl ? 'url' : 'value',
			'prefilter' => PreFilter::hit($parts),
			'pathExcluded' => $parts->pathExcluded,
			'minWeight' => $rules->minWeight,
			'maxBytes' => $rules->maxBytes,
			'signaturesVersion' => Signatures::VERSION,
			'fires' => $fires,
			'modes' => [
				'anonymous' => $this->settings->anonymousMode()->effective->value,
				'authenticated' => $this->settings->authenticatedMode()->effective->value,
			],
			'values' => $shown,
		];
	}

	private static function shown(string $text): string {
		$clean = preg_replace('~[\x00-\x08\x0b-\x1f\x7f]~', '', mb_scrub($text, 'UTF-8')) ?? '';
		return mb_substr($clean, 0, self::MAX_SHOWN);
	}
}
