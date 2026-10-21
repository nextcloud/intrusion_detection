<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Blocklist;

/**
 * One list the app can download: a blocklist (`deny`) or a network attribute
 * list (`hosting`, `tor`).
 *
 * For deny lists, `mode` says what a match does: `protect` refuses the
 * request, `observe` only counts it. Attribute lists have no mode; they only
 * describe the network an address belongs to.
 */
final class BlocklistSource {
	public const PURPOSE_DENY = 'deny';
	public const PURPOSE_HOSTING = 'hosting';
	public const PURPOSE_TOR = 'tor';
	public const PURPOSES = [self::PURPOSE_DENY, self::PURPOSE_HOSTING, self::PURPOSE_TOR];

	public const MODE_OBSERVE = 'observe';
	public const MODE_PROTECT = 'protect';
	public const MODES = [self::MODE_OBSERVE, self::MODE_PROTECT];

	public const ID_PATTERN = '/^[a-z][a-z0-9_]{1,31}$/';
	public const MIN_INTERVAL = 900;
	public const MAX_INTERVAL = 7 * 86400;

	/**
	 * @param ?int $interval seconds between syncs; null for the global sync interval
	 * @param ?string $termsUrl where the publisher states the terms of use
	 */
	public function __construct(
		public readonly string $id,
		public readonly string $name,
		public readonly string $url,
		public readonly ListFormat $format,
		public readonly string $purpose,
		public readonly ?string $mode,
		public readonly bool $enabled,
		public readonly ?int $interval,
		public readonly bool $builtin,
		public readonly ?string $termsUrl = null,
	) {
	}

	public function isDeny(): bool {
		return $this->purpose === self::PURPOSE_DENY;
	}

	public function isProtect(): bool {
		return $this->isDeny() && $this->mode === self::MODE_PROTECT;
	}

	public function effectiveInterval(int $globalInterval): int {
		return $this->interval ?? $globalInterval;
	}

	/**
	 * The attribute an address on this list gets in its verdict when the list
	 * does not refuse it: `list:<id>` for deny lists, `hosting` or `tor` otherwise.
	 */
	public function attribute(): string {
		return $this->isDeny() ? 'list:' . $this->id : $this->purpose;
	}

	/**
	 * The stored form in the `blocklist_sources` setting.
	 *
	 * @return array{id: string, url: string, purpose: string, format: string, mode?: string, enabled: bool, interval?: int}
	 */
	public function toStored(): array {
		$stored = [
			'id' => $this->id,
			'url' => $this->url,
			'purpose' => $this->purpose,
			'format' => $this->format->value,
			'enabled' => $this->enabled,
		];
		if ($this->mode !== null) {
			$stored['mode'] = $this->mode;
		}
		if ($this->interval !== null) {
			$stored['interval'] = $this->interval;
		}
		return $stored;
	}
}
