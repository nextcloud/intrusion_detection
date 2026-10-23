<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Explain;

use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Definition\CheckDefinition;
use OCA\IntrusionDetection\Definition\ParamDefinition;
use OCA\IntrusionDetection\Definition\ParamType;
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
	 * Text a request chose (a requested path, a parameter and its value, a
	 * client or session name), as the explanations quote it: printable
	 * characters only, and nothing a mail client or the notifications could
	 * turn into a link or an address. "://", "@" and the dots before a
	 * top-level domain or file extension are bracketed (`evil[.]example`), the way security reports quote such
	 * text; everything else stays as it was sent.
	 */
	public static function defused(string $text): string {
		$text = mb_scrub($text, 'UTF-8');
		// Control, format (bidi overrides), private-use and unassigned characters.
		$text = (string)(preg_replace('/\p{C}+/u', ' ', $text) ?? '');
		$text = str_replace(['://', '@'], ['[://]', '[@]'], $text);
		return (string)(preg_replace('/(?<=[\p{L}\p{N}])[.。．｡](?=\p{L}{2})/u', '[.]', $text) ?? '');
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

	/**
	 * A count for a sentence, as "about 120" when it was estimated from
	 * sampled attempts (a sample factor above 1).
	 */
	public static function estimated(int $count, ?int $sampleFactor, IL10N $l): string {
		return ($sampleFactor ?? 1) > 1 ? $l->t('about %s', [(string)$count]) : (string)$count;
	}

	/**
	 * "3 of them exist: alice, bob, carol." for the accounts an attack tried,
	 * or null when none of them exists.
	 *
	 * @param ?list<string> $targets
	 */
	public static function targets(?array $targets, IL10N $l): ?string {
		if ($targets === null || $targets === []) {
			return null;
		}
		return $l->n('%n of them exists: %s.', '%n of them exist: %s.', count($targets), [implode(', ', $targets)]);
	}
}
