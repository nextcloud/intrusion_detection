<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\InjectionProbe;

/**
 * The settings the matcher works with, in a ready-to-use form: the active
 * signatures (built-in minus disabled, plus custom), the weight a value needs
 * to count as a hit, the byte budget and the parameters never inspected.
 */
final class PayloadRules {
	/** Parameter names that hold secrets are never inspected, whatever the settings say */
	public const SECRET_NAME_PARTS = ['password', 'passwd', 'secret', 'token'];
	/** `q` is free text on search routes only; elsewhere it is inspected */
	public const SEARCH_QUERY_PARAM = 'q';

	public const EXCLUDED_SECRET = 'secret';
	public const EXCLUDED_FREE_TEXT = 'free_text';

	/** @var array<string, true> */
	private array $excluded = [];

	/**
	 * @param list<Signature> $signatures
	 * @param list<string> $excludedParams
	 */
	public function __construct(
		public readonly array $signatures,
		public readonly int $minWeight,
		public readonly int $maxBytes,
		array $excludedParams,
	) {
		foreach ($excludedParams as $name) {
			$this->excluded[strtolower($name)] = true;
		}
	}

	/**
	 * @param list<string> $disabled ids of signatures that do not run
	 * @param list<string> $custom custom signature entries, see {@see CustomSignatures}
	 * @param list<string> $excludedParams
	 */
	public static function build(int $minWeight, int $maxBytes, array $disabled, array $custom, array $excludedParams): self {
		$off = array_fill_keys($disabled, true);
		$signatures = array_values(array_filter(Signatures::builtIn(), static fn (Signature $s): bool => !isset($off[$s->id])));
		$parser = new CustomSignatures();
		foreach ($custom as $entry) {
			$signature = $parser->parse($entry);
			if ($signature !== null && !isset($off[$signature->id])) {
				$signatures[] = $signature;
			}
		}
		return new self($signatures, $minWeight, $maxBytes, $excludedParams);
	}

	/**
	 * Why a parameter is not inspected, or null when it is.
	 *
	 * @param string $name the decoded parameter name; for `a[b]` both `a` and the whole name are compared with the list
	 * @param bool $searchRoute whether the request goes to a search route
	 * @return self::EXCLUDED_*|null
	 */
	public function exclusion(string $name, bool $searchRoute): ?string {
		$lower = strtolower($name);
		foreach (self::SECRET_NAME_PARTS as $part) {
			if (str_contains($lower, $part)) {
				return self::EXCLUDED_SECRET;
			}
		}
		$bracket = strpos($lower, '[');
		$base = $bracket === false ? $lower : substr($lower, 0, $bracket);
		if (isset($this->excluded[$lower])) {
			return self::EXCLUDED_FREE_TEXT;
		}
		if (isset($this->excluded[$base]) || ($searchRoute && $base === self::SEARCH_QUERY_PARAM)) {
			return self::EXCLUDED_FREE_TEXT;
		}
		return null;
	}
}
