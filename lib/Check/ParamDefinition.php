<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check;

/**
 * One configurable parameter of a check, with its type, default and allowed range.
 *
 * The same definition drives the config lexicon, the admin API, occ and the
 * placeholders in the explanation texts, so a parameter is validated the same
 * way wherever it is set.
 */
final class ParamDefinition {
	/** Longest accepted value of a ParamType::Json setting, in bytes */
	public const MAX_JSON_LENGTH = 262144;

	/**
	 * @param int|float|bool|string|list<string> $default
	 * @param list<string> $choices allowed values for ParamType::Choice
	 * @param ?string $itemPattern regular expression every list item must match (StringList)
	 * @param int $maxItems maximum number of list items
	 * @param int $maxItemLength maximum length of one list item
	 * @param ?\Closure(string, bool): ?string $itemValidator extra check of one StringList item, given the item and whether to be thorough (when saving); returns why it is invalid, or null
	 */
	public function __construct(
		public readonly string $name,
		public readonly ParamType $type,
		public readonly int|float|bool|string|array $default,
		public readonly int|float|null $min = null,
		public readonly int|float|null $max = null,
		public readonly array $choices = [],
		public readonly ?string $itemPattern = null,
		public readonly int $maxItems = 200,
		public readonly int $maxItemLength = 255,
		public readonly ?\Closure $itemValidator = null,
	) {
		if (!preg_match('/^[a-z][a-z0-9_]*$/', $name)) {
			throw new \InvalidArgumentException('Invalid parameter name: ' . $name);
		}
		// The default must itself be valid, so a definition cannot drift from its own rules.
		$this->validate($default);
	}

	/**
	 * Validate a value and return it in its canonical type.
	 *
	 * @param bool $thorough also run expensive item checks; done when a value is saved, not on every read
	 * @return int|float|bool|string|list<string>
	 * @throws InvalidParamException
	 */
	public function validate(mixed $value, bool $thorough = false): int|float|bool|string|array {
		return match ($this->type) {
			ParamType::Int, ParamType::Duration => $this->validateInt($value),
			ParamType::Float => $this->validateFloat($value),
			ParamType::Bool => $this->validateBool($value),
			ParamType::Choice => $this->validateChoice($value),
			ParamType::StringList => $this->validateStringList($value, $thorough),
			ParamType::CidrList => $this->validateCidrList($value),
			ParamType::Json => $this->validateJson($value),
		};
	}

	/**
	 * Parse a value typed on the command line or in a form field. Lists are
	 * comma-separated, or a JSON array for items that contain commas.
	 *
	 * @return int|float|bool|string|list<string>
	 * @throws InvalidParamException
	 */
	public function parse(string $raw): int|float|bool|string|array {
		$raw = trim($raw);
		return match ($this->type) {
			ParamType::Int => $this->validateInt($raw),
			ParamType::Duration => $this->validateInt(self::parseDuration($raw)),
			ParamType::Float => $this->validateFloat($raw),
			ParamType::Bool => $this->validateBool($raw),
			ParamType::Choice => $this->validateChoice($raw),
			ParamType::StringList, ParamType::CidrList => $this->validate(self::parseList($raw)),
			ParamType::Json => $this->validateJson($raw),
		};
	}

	/**
	 * The raw list as typed, for validate() to check.
	 */
	private static function parseList(string $raw): mixed {
		if (str_starts_with($raw, '[')) {
			try {
				return json_decode($raw, true, 4, JSON_THROW_ON_ERROR);
			} catch (\JsonException) {
				return null;
			}
		}
		return $raw === '' ? [] : array_values(array_filter(array_map('trim', explode(',', $raw)), static fn (string $s): bool => $s !== ''));
	}

	/**
	 * Accept plain seconds or a number with a unit: 90, 90s, 10m, 4h, 7d.
	 *
	 * @throws InvalidParamException
	 */
	public static function parseDuration(string $raw): int {
		if (!preg_match('/^(\d{1,9})\s*([smhd]?)$/i', trim($raw), $m)) {
			throw new InvalidParamException('not_a_duration', ['value' => $raw]);
		}
		return (int)$m[1] * match (strtolower($m[2])) {
			'm' => 60,
			'h' => 3600,
			'd' => 86400,
			default => 1,
		};
	}

	/**
	 * @return array{name: string, type: string, default: int|float|bool|string|list<string>, min: int|float|null, max: int|float|null, choices: list<string>}
	 */
	public function toArray(): array {
		return [
			'name' => $this->name,
			'type' => $this->type->value,
			'default' => $this->default,
			'min' => $this->min,
			'max' => $this->max,
			'choices' => $this->choices,
		];
	}

	private function validateInt(mixed $value): int {
		if (is_string($value) && preg_match('/^-?\d{1,18}$/', $value)) {
			$value = (int)$value;
		}
		if (!is_int($value)) {
			throw new InvalidParamException('not_an_integer', ['param' => $this->name]);
		}
		$this->checkBounds($value);
		return $value;
	}

	private function validateFloat(mixed $value): float {
		if (is_string($value) && is_numeric($value)) {
			$value = (float)$value;
		}
		if (is_int($value)) {
			$value = (float)$value;
		}
		if (!is_float($value) || !is_finite($value)) {
			throw new InvalidParamException('not_a_number', ['param' => $this->name]);
		}
		$this->checkBounds($value);
		return $value;
	}

	private function checkBounds(int|float $value): void {
		if ($this->min !== null && $value < $this->min) {
			throw new InvalidParamException('too_small', ['param' => $this->name, 'min' => $this->min]);
		}
		if ($this->max !== null && $value > $this->max) {
			throw new InvalidParamException('too_large', ['param' => $this->name, 'max' => $this->max]);
		}
	}

	private function validateBool(mixed $value): bool {
		if (is_bool($value)) {
			return $value;
		}
		if (is_string($value)) {
			$lower = strtolower($value);
			if (in_array($lower, ['1', 'true', 'yes', 'on'], true)) {
				return true;
			}
			if (in_array($lower, ['0', 'false', 'no', 'off'], true)) {
				return false;
			}
		}
		if ($value === 0 || $value === 1) {
			return $value === 1;
		}
		throw new InvalidParamException('not_a_boolean', ['param' => $this->name]);
	}

	private function validateChoice(mixed $value): string {
		if (!is_string($value) || !in_array($value, $this->choices, true)) {
			throw new InvalidParamException('not_a_choice', ['param' => $this->name, 'choices' => implode(', ', $this->choices)]);
		}
		return $value;
	}

	/**
	 * @return list<string>
	 */
	private function validateStringList(mixed $value, bool $thorough): array {
		$items = $this->listItems($value);
		foreach ($items as $item) {
			if ($this->itemPattern !== null && preg_match($this->itemPattern, $item) !== 1) {
				throw new InvalidParamException('invalid_item', ['param' => $this->name, 'item' => self::excerpt($item)]);
			}
			$problem = $this->itemValidator === null ? null : ($this->itemValidator)($item, $thorough);
			if ($problem !== null) {
				throw new InvalidParamException('invalid_pattern', ['param' => $this->name, 'item' => self::excerpt($item), 'why' => $problem]);
			}
		}
		return $items;
	}

	/**
	 * @return list<string>
	 */
	private function validateCidrList(mixed $value): array {
		$items = $this->listItems($value);
		foreach ($items as $i => $item) {
			// A single address is accepted as the smallest range that contains it.
			if (!str_contains($item, '/')) {
				$item .= str_contains($item, ':') ? '/128' : '/32';
			}
			if (!self::isValidCidr($item)) {
				throw new InvalidParamException('invalid_range', ['param' => $this->name, 'item' => self::excerpt($item)]);
			}
			$items[$i] = strtolower($item);
		}
		return $items;
	}

	/**
	 * @return list<string>
	 */
	private function listItems(mixed $value): array {
		if (!is_array($value) || !array_is_list($value)) {
			throw new InvalidParamException('not_a_list', ['param' => $this->name]);
		}
		if (count($value) > $this->maxItems) {
			throw new InvalidParamException('too_many_items', ['param' => $this->name, 'max' => $this->maxItems]);
		}
		$items = [];
		foreach ($value as $item) {
			if (!is_string($item)) {
				throw new InvalidParamException('invalid_item', ['param' => $this->name, 'item' => '']);
			}
			$item = trim($item);
			if ($item === '' || strlen($item) > $this->maxItemLength || preg_match('/[\x00-\x1f\x7f]/', $item)) {
				throw new InvalidParamException('invalid_item', ['param' => $this->name, 'item' => self::excerpt($item)]);
			}
			$items[] = $item;
		}
		return array_values(array_unique($items));
	}

	/**
	 * A JSON object or list, as text. Arrays are encoded. Only the syntax and
	 * the size are checked here.
	 */
	private function validateJson(mixed $value): string {
		if (is_array($value)) {
			$value = json_encode($value, JSON_UNESCAPED_SLASHES);
		}
		if (!is_string($value) || strlen($value) > self::MAX_JSON_LENGTH) {
			throw new InvalidParamException('not_json', ['param' => $this->name]);
		}
		try {
			$decoded = json_decode($value, true, 32, JSON_THROW_ON_ERROR);
		} catch (\JsonException) {
			throw new InvalidParamException('not_json', ['param' => $this->name]);
		}
		if (!is_array($decoded)) {
			throw new InvalidParamException('not_json', ['param' => $this->name]);
		}
		return $value;
	}

	private static function isValidCidr(string $range): bool {
		if (!preg_match('#^([0-9a-fA-F:.]+)/(\d{1,3})$#', $range, $m)) {
			return false;
		}
		if (filter_var($m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
			return (int)$m[2] <= 32;
		}
		if (filter_var($m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
			return (int)$m[2] <= 128;
		}
		return false;
	}

	private static function excerpt(string $value): string {
		$value = preg_replace('/[\x00-\x1f\x7f]/', '', $value) ?? '';
		return mb_strlen($value) > 40 ? mb_substr($value, 0, 40) . '…' : $value;
	}
}
