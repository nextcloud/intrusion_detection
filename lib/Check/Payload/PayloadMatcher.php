<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Payload;

/**
 * Weighs one value against the signatures.
 *
 * The value is normalised and matched; if it, or one of its path segments,
 * is base64 text, every decoded level is matched too, including the
 * signatures that only apply to decoded text. Each form is weighed on its
 * own: the weights of the distinct signatures that matched it are added up.
 * The value is a hit when one form reaches the rules' minimum weight.
 *
 * A pattern that fails (for example on PCRE's backtracking limit) counts as
 * no match.
 */
class PayloadMatcher {
	public const EXCERPT_LENGTH = 200;
	/** Characters shown before the first match in an excerpt */
	public const EXCERPT_LEAD = 40;
	/** At most this many path segments are tried as base64 */
	public const MAX_SEGMENTS = 32;

	public function __construct(
		private readonly Normalizer $normalizer,
		private readonly Base64Inspector $base64,
	) {
	}

	/**
	 * @param string $raw the value as sent (percent-encoded for paths and query strings)
	 * @param bool $isPath split into segments for the base64 test
	 */
	public function analyse(string $raw, PayloadRules $rules, bool $isPath = false): ValueAnalysis {
		$forms = [$this->weigh(FormMatch::ENCODING_NONE, $this->normalizer->normalize($raw), $rules, false)];
		$decodedTexts = [];
		foreach ($this->base64Candidates($raw, $isPath) as $candidate) {
			foreach ($this->base64->decode($candidate) as $index => $decoded) {
				$decodedTexts[] = $decoded;
				$forms[] = $this->weigh(FormMatch::encodingFor($index + 1), $this->normalizer->normalize($decoded), $rules, true);
			}
		}
		return new ValueAnalysis($decodedTexts, $forms, $rules->minWeight);
	}

	/**
	 * @param FormMatch::ENCODING_* $encoding
	 */
	public function weigh(string $encoding, string $text, PayloadRules $rules, bool $decoded): FormMatch {
		$matches = [];
		$offset = -1;
		$needsOther = [];
		foreach ($rules->signatures as $signature) {
			if (!$signature->appliesTo($decoded)) {
				continue;
			}
			$position = self::position($signature, $text);
			if ($position === null) {
				continue;
			}
			if ($signature->requiresOther) {
				$needsOther[$signature->id] = [$signature->weight, $position];
				continue;
			}
			$matches[$signature->id] = $signature->weight;
			$offset = $offset < 0 ? $position : min($offset, $position);
		}
		if ($matches !== []) {
			foreach ($needsOther as $id => [$weight, $position]) {
				$matches[$id] = $weight;
				$offset = min($offset, $position);
			}
		}
		return new FormMatch($encoding, $text, $matches, array_sum($matches), $offset);
	}

	/**
	 * At most EXCERPT_LENGTH characters of the matched text, starting a little
	 * before the first match, as valid UTF-8 without control characters.
	 */
	public static function excerpt(FormMatch $form): string {
		$start = max(0, $form->offset - self::EXCERPT_LEAD);
		$cut = mb_scrub(substr($form->text, $start, self::EXCERPT_LENGTH * 4), 'UTF-8');
		$clean = preg_replace('~[\x00-\x1f\x7f]|\xc2[\x80-\x9f]~', '', $cut) ?? '';
		return mb_substr($clean, 0, self::EXCERPT_LENGTH);
	}

	private static function position(Signature $signature, string $text): ?int {
		if ($signature->custom) {
			$result = CustomSignatures::run($signature->pattern, $text, $m);
		} else {
			$result = preg_match($signature->pattern, $text, $m, PREG_OFFSET_CAPTURE);
		}
		if ($result !== 1) {
			return null;
		}
		return max(0, (int)$m[0][1]);
	}

	/**
	 * @return list<string>
	 */
	private function base64Candidates(string $raw, bool $isPath): array {
		if (!$isPath) {
			$value = Base64Inspector::formCandidate($raw);
			return strlen($value) >= Base64Inspector::MIN_LENGTH ? [$value] : [];
		}
		$value = Normalizer::urlDecode($raw);
		$candidates = [];
		foreach (explode('/', $value) as $segment) {
			if (strlen($segment) >= Base64Inspector::MIN_LENGTH) {
				$candidates[] = $segment;
				if (count($candidates) >= self::MAX_SEGMENTS) {
					break;
				}
			}
		}
		return $candidates;
	}
}
