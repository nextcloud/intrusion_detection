<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Blocklist;

use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Response\BanService;

/**
 * Reads the list definitions: the built-in lists, with what the administrator
 * chose for them, and the administrator's own lists, from the
 * `blocklist_sources` setting.
 *
 * Entries that do not validate are ignored here; {@see SourceEditor}
 * validates before it saves. Kept light, because the address check uses it on
 * a cold cache.
 */
class SourceRepository {
	public const MAX_SOURCES = 50;
	public const REFERENCE_PREFIX = 'LIST-';
	private const REFERENCE_LENGTH = 6;

	private ?string $loadedFrom = null;
	/** @var array<string, BlocklistSource> */
	private array $sources = [];

	public function __construct(
		private readonly AppSettings $settings,
		private readonly Fingerprinter $fingerprinter,
	) {
	}

	/**
	 * @return array<string, BlocklistSource> keyed by id, the built-in lists first
	 */
	public function all(): array {
		$raw = $this->settings->blocklistSources();
		if ($raw !== $this->loadedFrom) {
			$this->sources = self::fromStored($raw);
			$this->loadedFrom = $raw;
		}
		return $this->sources;
	}

	public function get(string $id): ?BlocklistSource {
		return $this->all()[$id] ?? null;
	}

	/**
	 * @return list<BlocklistSource>
	 */
	public function enabled(): array {
		return array_values(array_filter($this->all(), static fn (BlocklistSource $s): bool => $s->enabled));
	}

	public function hasEnabled(): bool {
		return $this->enabled() !== [];
	}

	/**
	 * The reference a request refused by this list is given, e.g. LIST-K7Q2MP.
	 *
	 * It is keyed with the instance secret, so the visitor cannot tell which
	 * list refused them; the administrator looks it up with
	 * occ intrusion:blocklists:list or on the admin page.
	 */
	public function reference(string $id): string {
		$hash = $this->fingerprinter->name('blocklist/' . $id);
		$chars = BanService::REFERENCE_CHARS;
		$reference = '';
		for ($i = 0; $i < self::REFERENCE_LENGTH; $i++) {
			$reference .= $chars[ord($hash[$i]) % strlen($chars)];
		}
		return self::REFERENCE_PREFIX . $reference;
	}

	/**
	 * The list a reference belongs to, typed in any case, with or without the dash.
	 */
	public function findByReference(string $reference): ?BlocklistSource {
		$wanted = strtoupper(str_replace(['-', ' '], '', trim($reference)));
		foreach ($this->all() as $source) {
			if (str_replace('-', '', $this->reference($source->id)) === $wanted) {
				return $source;
			}
		}
		return null;
	}

	/**
	 * @return array<string, BlocklistSource>
	 */
	public static function fromStored(string $raw): array {
		$sources = BuiltinSources::all();
		$stored = json_decode($raw, true);
		if (!is_array($stored)) {
			return $sources;
		}
		foreach (array_slice($stored, 0, self::MAX_SOURCES) as $entry) {
			if (!is_array($entry) || !is_string($entry['id'] ?? null) || !preg_match(BlocklistSource::ID_PATTERN, $entry['id'])) {
				continue;
			}
			$id = $entry['id'];
			$enabled = ($entry['enabled'] ?? false) === true;
			$interval = self::interval($entry['interval'] ?? null);
			$builtin = $sources[$id] ?? null;
			if ($builtin !== null && $builtin->builtin) {
				$mode = self::mode($entry['mode'] ?? null) ?? $builtin->mode;
				$sources[$id] = new BlocklistSource(
					$id, $builtin->name, $builtin->url, $builtin->format, $builtin->purpose,
					$builtin->isDeny() ? $mode : null, $enabled, $interval ?? $builtin->interval, true, $builtin->termsUrl,
				);
				continue;
			}
			$url = $entry['url'] ?? null;
			$purpose = $entry['purpose'] ?? null;
			$format = is_string($entry['format'] ?? null) ? ListFormat::tryFrom($entry['format']) : ListFormat::Cidr;
			if (isset($sources[$id]) || !is_string($url) || !UrlPolicy::hasValidShape($url)
				|| !in_array($purpose, BlocklistSource::PURPOSES, true) || $format === null) {
				continue;
			}
			$isDeny = $purpose === BlocklistSource::PURPOSE_DENY;
			$sources[$id] = new BlocklistSource(
				$id, $id, $url, $format, $purpose,
				$isDeny ? (self::mode($entry['mode'] ?? null) ?? BlocklistSource::MODE_OBSERVE) : null,
				$enabled, $interval, false,
				sha256: is_string($entry['sha256'] ?? null) && preg_match(BlocklistSource::SHA256_PATTERN, $entry['sha256']) ? $entry['sha256'] : null,
			);
		}
		return $sources;
	}

	/**
	 * @return BlocklistSource::MODE_*|null
	 */
	private static function mode(mixed $mode): ?string {
		return is_string($mode) && in_array($mode, BlocklistSource::MODES, true) ? $mode : null;
	}

	private static function interval(mixed $interval): ?int {
		return is_int($interval) && $interval >= BlocklistSource::MIN_INTERVAL && $interval <= BlocklistSource::MAX_INTERVAL ? $interval : null;
	}
}
