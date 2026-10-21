<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Config;

use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\ParamDefinition;
use OCA\IntrusionDetection\Check\Requirement;
use OCA\IntrusionDetection\Check\ResponseType;

/**
 * Builds the static data of {@see LexiconData} from the check registry and
 * the global settings, which stay the single source of truth. A unit test
 * compares both and rewrites LexiconData.php when asked to
 * (`IDS_WRITE_LEXICON_DATA=1`).
 *
 * @psalm-import-type ParamSpec from LexiconData
 * @psalm-import-type CheckSpec from LexiconData
 */
final class LexiconDataBuilder {
	public function __construct(
		private readonly CheckRegistry $registry,
		private readonly GlobalSettings $globals,
	) {
	}

	/**
	 * @return array<string, ParamSpec>
	 */
	public function globals(): array {
		$specs = [];
		foreach ($this->globals->all() as $name => $definition) {
			$specs[$name] = self::param($definition);
		}
		return $specs;
	}

	/**
	 * @return array<string, CheckSpec>
	 */
	public function checks(): array {
		$specs = [];
		foreach ($this->registry->all() as $id => $check) {
			$params = [];
			foreach ($check->params as $param) {
				$params[$param->name] = self::param($param);
			}
			$specs[$id] = [
				'mode' => $check->defaultMode->value,
				'responses' => array_map(static fn (ResponseType $r): string => $r->value, $check->defaultResponses),
				'allowed' => array_map(static fn (ResponseType $r): string => $r->value, $check->responses),
				'requirements' => array_map(static fn (Requirement $r): string => $r->value, $check->requirements),
				'learning' => $check->actsWhileLearning,
				'onlyNotifies' => $check->onlyNotifies(),
				'params' => $params,
			];
		}
		return $specs;
	}

	/**
	 * The source of LexiconData.php.
	 */
	public function source(): string {
		$header = file_get_contents(__DIR__ . '/LexiconData.php');
		$start = is_string($header) ? strpos($header, "\tpublic const GLOBALS") : false;
		if (!is_string($header) || $start === false) {
			throw new \RuntimeException('LexiconData.php has no GLOBALS constant');
		}
		return substr($header, 0, $start)
			. "\tpublic const GLOBALS = " . self::export($this->globals(), 1) . ";\n\n"
			. "\t/** @var array<string, CheckSpec> */\n"
			. "\tpublic const CHECKS = " . self::export($this->checks(), 1) . ";\n}\n";
	}

	/**
	 * Only what differs from the defaults of {@see ParamDefinition} is kept.
	 *
	 * @return ParamSpec
	 */
	public static function param(ParamDefinition $definition): array {
		$spec = ['type' => $definition->type->value, 'default' => $definition->default];
		if ($definition->min !== null) {
			$spec['min'] = $definition->min;
		}
		if ($definition->max !== null) {
			$spec['max'] = $definition->max;
		}
		if ($definition->choices !== []) {
			$spec['choices'] = $definition->choices;
		}
		if ($definition->itemPattern !== null) {
			$spec['pattern'] = $definition->itemPattern;
		}
		if ($definition->maxItems !== 200) {
			$spec['maxItems'] = $definition->maxItems;
		}
		if ($definition->maxItemLength !== 255) {
			$spec['maxItemLength'] = $definition->maxItemLength;
		}
		if ($definition->itemValidator !== null) {
			$spec['validator'] = true;
		}
		return $spec;
	}

	private static function export(mixed $value, int $depth): string {
		if (!is_array($value)) {
			return var_export($value, true);
		}
		if ($value === []) {
			return '[]';
		}
		$indent = str_repeat("\t", $depth + 1);
		$lines = [];
		$list = array_is_list($value);
		foreach ($value as $key => $item) {
			$lines[] = $indent . ($list ? '' : var_export($key, true) . ' => ') . self::export($item, $depth + 1) . ',';
		}
		return "[\n" . implode("\n", $lines) . "\n" . str_repeat("\t", $depth) . ']';
	}
}
