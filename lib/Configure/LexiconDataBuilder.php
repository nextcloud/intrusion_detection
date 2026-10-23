<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Configure;

use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Keys;
use OCA\IntrusionDetection\Config\LexiconData;
use OCA\IntrusionDetection\Definition\CheckDefinition;
use OCA\IntrusionDetection\Definition\ParamDefinition;
use OCA\IntrusionDetection\Definition\ParamType;
use OCA\IntrusionDetection\Definition\Requirement;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\State\HotState;
use OCP\Config\ValueType;

/**
 * Builds the static data of {@see LexiconData} from the check registry and
 * the global settings, which stay the single source of truth. A unit test
 * compares both and rewrites LexiconData.php when asked to
 * (`IDS_WRITE_LEXICON_DATA=1`).
 *
 * @psalm-import-type ParamSpec from LexiconData
 * @psalm-import-type CheckSpec from LexiconData
 * @psalm-import-type EntrySpec from LexiconData
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
	 * The checks that the config.php lock holds in Protect.
	 *
	 * @return list<string>
	 */
	public function lockedChecks(): array {
		return array_values(array_map(static fn (CheckDefinition $c): string => $c->id, array_filter($this->registry->all(), static fn (CheckDefinition $c): bool => $c->heldByLock)));
	}

	/**
	 * Every app config key with its value type, default and description, in
	 * the order of the config lexicon: the global settings, the internal
	 * state in {@see HotState}, then per check its mode, its responses and
	 * its parameters.
	 *
	 * @return list<EntrySpec>
	 */
	public function entries(): array {
		$entries = [];
		foreach ($this->globals() as $name => $spec) {
			$entries[] = [$name, ParamType::from($spec['type'])->valueType(), $spec['default'], 'intrusion detection: ' . $name];
		}
		foreach (HotState::LEXICON as $key => [$type, $default]) {
			$entries[] = [$key, $type, $default, 'intrusion detection: ' . $key];
		}
		foreach ($this->checks() as $id => $check) {
			$entries[] = [Keys::mode($id), ValueType::STRING, $check['mode'], 'mode of the ' . $id . ' check'];
			$entries[] = [Keys::responses($id), ValueType::ARRAY, $check['responses'], 'responses of the ' . $id . ' check'];
			foreach ($check['params'] as $name => $spec) {
				$entries[] = [Keys::param($id, $name), ParamType::from($spec['type'])->valueType(), $spec['default'], $id . ' check: ' . $name];
			}
		}
		return $entries;
	}

	/**
	 * The source of LexiconData.php.
	 */
	public function source(): string {
		$header = file_get_contents(__DIR__ . '/../Config/LexiconData.php');
		$start = is_string($header) ? strpos($header, "\tpublic const GLOBALS") : false;
		if (!is_string($header) || $start === false) {
			throw new \RuntimeException('LexiconData.php has no GLOBALS constant');
		}
		return substr($header, 0, $start)
			. "\tpublic const GLOBALS = " . self::export($this->globals(), 1) . ";\n\n"
			. "\t/** @var array<string, CheckSpec> */\n"
			. "\tpublic const CHECKS = " . self::export($this->checks(), 1) . ";\n\n"
			. "\t/** @var list<string> the checks the config.php lock holds in Protect */\n"
			. "\tpublic const LOCKED_CHECKS = " . self::export($this->lockedChecks(), 1) . ";\n\n"
			. "\t/** @var list<EntrySpec> */\n"
			. "\tpublic const ENTRIES = [\n" . implode('', array_map(static fn (array $entry): string => "\t\t" . self::inline($entry) . ",\n", $this->entries())) . "\t];\n}\n";
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
		return $spec;
	}

	/**
	 * A value on one line.
	 */
	private static function inline(mixed $value): string {
		if ($value instanceof ValueType) {
			return 'ValueType::' . $value->name;
		}
		if (!is_array($value)) {
			return var_export($value, true);
		}
		$list = array_is_list($value);
		$items = [];
		foreach ($value as $key => $item) {
			$items[] = ($list ? '' : var_export($key, true) . ' => ') . self::inline($item);
		}
		return '[' . implode(', ', $items) . ']';
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
