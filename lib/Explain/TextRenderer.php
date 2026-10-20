<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Explain;

use OCA\IntrusionDetection\Check\CheckDefinition;
use OCA\IntrusionDetection\Check\ParamDefinition;
use OCA\IntrusionDetection\Check\ParamType;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCP\IL10N;

/**
 * Fills the `{name}` placeholders of explanation templates with formatted
 * values: durations as "10 minutes", lists joined, booleans as on/off.
 *
 * The admin page does the same in the browser while the admin types; this is
 * the server-side counterpart for occ, emails and stored narratives.
 */
class TextRenderer {
	public function __construct(
		private readonly GlobalSettings $globals,
	) {
	}

	/**
	 * @param array<string, int|float|bool|string|list<string>> $values
	 */
	public function fill(string $template, array $values, IL10N $l, ?CheckDefinition $check = null): string {
		return (string)preg_replace_callback('/\{([a-z][a-z0-9_]*)\}/', function (array $m) use ($values, $l, $check): string {
			$name = $m[1];
			if (!array_key_exists($name, $values)) {
				return $m[0];
			}
			$definition = $check !== null && $check->hasParam($name) ? $check->param($name) : $this->globals->get($name);
			return $this->format($values[$name], $definition, $l);
		}, $template);
	}

	public function format(int|float|bool|string|array $value, ?ParamDefinition $definition, IL10N $l): string {
		if ($definition?->type === ParamType::Duration && is_int($value)) {
			return self::duration($value, $l);
		}
		if (is_bool($value)) {
			return $value ? $l->t('on') : $l->t('off');
		}
		if (is_array($value)) {
			return $value === [] ? $l->t('none') : implode(', ', $value);
		}
		if (is_float($value)) {
			return rtrim(rtrim(number_format($value, 2, '.', ''), '0'), '.');
		}
		return (string)$value;
	}

	/**
	 * A duration in the largest whole unit: "90 seconds", "10 minutes", "4 hours", "7 days".
	 */
	public static function duration(int $seconds, IL10N $l): string {
		if ($seconds >= 86400 && $seconds % 86400 === 0) {
			return $l->n('%n day', '%n days', intdiv($seconds, 86400));
		}
		if ($seconds >= 3600 && $seconds % 3600 === 0) {
			return $l->n('%n hour', '%n hours', intdiv($seconds, 3600));
		}
		if ($seconds >= 60 && $seconds % 60 === 0) {
			return $l->n('%n minute', '%n minutes', intdiv($seconds, 60));
		}
		return $l->n('%n second', '%n seconds', $seconds);
	}
}
