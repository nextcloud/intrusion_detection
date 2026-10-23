<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Detection;

use OCA\IntrusionDetection\Config\ModeState;

/**
 * Builds the explanation record a detection stores: everything needed to say
 * later why it happened, even after the settings changed.
 */
final class Explanation {
	/** Bump when the structure changes, so old records can still be rendered */
	public const VERSION = 1;
	/** At most this many user ids are kept as targets */
	public const MAX_TARGETS = 20;
	public const MAX_USER_AGENT = 200;

	/**
	 * @param array<string, int|float|bool|string|list<string>> $thresholds the parameters in force
	 * @return array<string, mixed>
	 */
	public static function build(DetectionDraft $draft, ModeState $mode, array $thresholds, int $now): array {
		return [
			'v' => self::VERSION,
			'check' => $draft->checkId,
			'mode' => [
				'configured' => $mode->configured->value,
				'effective' => $mode->effective->value,
				'reason' => $mode->reason,
			],
			'thresholds' => $thresholds,
			'source' => $draft->source === null ? null : [
				'ip' => $draft->source->ip,
				'net' => $draft->source->netKey,
				'family' => $draft->source->family,
			],
			'userAgent' => self::cleanUserAgent($draft->userAgent),
			'facts' => $draft->facts,
			'first' => $now,
			'last' => $now,
		];
	}

	/**
	 * Truncated and stripped of control characters, so it is safe to store and show.
	 */
	public static function cleanUserAgent(?string $userAgent): ?string {
		if ($userAgent === null || $userAgent === '') {
			return null;
		}
		$clean = preg_replace('/[\x00-\x1f\x7f]+/u', ' ', $userAgent) ?? '';
		$clean = trim($clean);
		return $clean === '' ? null : mb_substr($clean, 0, self::MAX_USER_AGENT);
	}
}
