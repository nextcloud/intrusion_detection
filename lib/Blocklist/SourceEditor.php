<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Blocklist;

use OCA\IntrusionDetection\Address\AddressCache;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Configure\SettingsEditor;
use OCA\IntrusionDetection\Definition\InvalidParamException;

/**
 * Changes the list definitions, with the same validation for occ and the
 * admin page: custom addresses must pass {@see UrlPolicy} when they are
 * saved, not only when they are downloaded. Every change is audited and
 * invalidates the cached verdicts.
 */
class SourceEditor {
	public function __construct(
		private readonly SourceRepository $sources,
		private readonly UrlPolicy $urlPolicy,
		private readonly SettingsEditor $settings,
		private readonly AddressCache $addressCache,
		private readonly AuditLogger $audit,
	) {
	}

	/**
	 * Create a custom list or change an existing one. An `interval` of null
	 * goes back to the list's default interval; a `sha256` of null or ''
	 * removes the pin of a custom list.
	 *
	 * @param array{enabled?: bool, mode?: string, interval?: ?int, url?: string, purpose?: string, format?: string, sha256?: ?string} $changes
	 * @throws InvalidParamException
	 */
	public function set(string $id, array $changes, string $actor): BlocklistSource {
		if (!preg_match(BlocklistSource::ID_PATTERN, $id)) {
			throw new InvalidParamException('invalid_list_id', ['param' => 'id']);
		}
		$all = $this->sources->all();
		$existing = $all[$id] ?? null;
		$definitionChange = isset($changes['url']) || isset($changes['purpose']) || isset($changes['format']) || array_key_exists('sha256', $changes);
		if ($existing !== null && $existing->builtin && $definitionChange) {
			throw new InvalidParamException('builtin_list', ['param' => 'url']);
		}

		$url = $changes['url'] ?? $existing?->url;
		$purpose = $changes['purpose'] ?? $existing?->purpose;
		if ($url === null || $purpose === null) {
			throw new InvalidParamException('list_needs_url', ['param' => 'url']);
		}
		if (!in_array($purpose, BlocklistSource::PURPOSES, true)) {
			throw new InvalidParamException('not_a_choice', ['param' => 'purpose', 'choices' => implode(', ', BlocklistSource::PURPOSES)]);
		}
		$format = ListFormat::tryFrom($changes['format'] ?? $existing?->format->value ?? ListFormat::Cidr->value);
		if ($format === null) {
			throw new InvalidParamException('not_a_choice', ['param' => 'format', 'choices' => implode(', ', array_map(static fn (ListFormat $f): string => $f->value, ListFormat::cases()))]);
		}
		if (($existing === null || !$existing->builtin) && !$this->urlPolicy->isAllowed($url)) {
			throw new InvalidParamException('url_refused', ['param' => 'url']);
		}
		$mode = $changes['mode'] ?? $existing?->mode ?? BlocklistSource::MODE_OBSERVE;
		if (!in_array($mode, BlocklistSource::MODES, true)) {
			throw new InvalidParamException('not_a_choice', ['param' => 'mode', 'choices' => implode(', ', BlocklistSource::MODES)]);
		}
		$interval = array_key_exists('interval', $changes) ? $changes['interval'] : $existing?->interval;
		if ($interval !== null && $interval < BlocklistSource::MIN_INTERVAL) {
			throw new InvalidParamException('too_small', ['param' => 'interval', 'min' => BlocklistSource::MIN_INTERVAL]);
		}
		if ($interval !== null && $interval > BlocklistSource::MAX_INTERVAL) {
			throw new InvalidParamException('too_large', ['param' => 'interval', 'max' => BlocklistSource::MAX_INTERVAL]);
		}
		if ($existing === null && count($all) >= SourceRepository::MAX_SOURCES) {
			throw new InvalidParamException('too_many_lists', ['param' => 'id', 'max' => SourceRepository::MAX_SOURCES]);
		}
		$sha256 = array_key_exists('sha256', $changes) ? strtolower(trim((string)$changes['sha256'])) : ($existing?->sha256 ?? '');
		if ($sha256 !== '' && !preg_match(BlocklistSource::SHA256_PATTERN, $sha256)) {
			throw new InvalidParamException('invalid_sha256', ['param' => 'sha256']);
		}
		if ($existing !== null && $existing->builtin && array_key_exists('interval', $changes) && $changes['interval'] === null) {
			$interval = BuiltinSources::all()[$id]->interval;
		}

		$source = new BlocklistSource(
			$id,
			$existing?->name ?? $id,
			$url,
			$format,
			$purpose,
			$purpose === BlocklistSource::PURPOSE_DENY ? $mode : null,
			$changes['enabled'] ?? $existing?->enabled ?? false,
			$interval,
			$existing !== null && $existing->builtin,
			$existing?->termsUrl,
			$sha256 === '' ? null : $sha256,
		);
		$all[$id] = $source;
		$this->save($all);
		$this->audit->log('blocklist %s changed by %s: %s, mode %s, %s, %s', [
			'list' => $id,
			'actor' => $actor,
			'state' => $source->enabled ? 'enabled' : 'disabled',
			'mode' => $source->mode ?? $source->purpose,
			'url' => $source->url,
			'sha256' => $source->sha256 === null ? 'no pinned SHA-256' : 'SHA-256 ' . $source->sha256,
		]);
		return $source;
	}

	/**
	 * Remove a custom list. Its ranges and counters go with the next cleanup.
	 *
	 * @throws InvalidParamException
	 */
	public function remove(string $id, string $actor): void {
		$all = $this->sources->all();
		$existing = $all[$id] ?? throw new InvalidParamException('unknown_list', ['list' => $id]);
		if ($existing->builtin) {
			throw new InvalidParamException('builtin_list');
		}
		unset($all[$id]);
		$this->save($all);
		$this->audit->log('blocklist %s removed by %s', ['list' => $id, 'actor' => $actor]);
	}

	/**
	 * @param array<string, BlocklistSource> $sources
	 */
	private function save(array $sources): void {
		$stored = [];
		foreach ($sources as $source) {
			// Built-in lists that are untouched need no entry.
			$builtin = BuiltinSources::all()[$source->id] ?? null;
			if ($builtin !== null && $source->builtin && !$source->enabled && $source->mode === $builtin->mode && $source->interval === $builtin->interval) {
				continue;
			}
			$stored[] = $source->toStored();
		}
		$this->settings->setGlobal(GlobalSettings::BLOCKLIST_SOURCES, json_encode($stored, JSON_UNESCAPED_SLASHES));
		$this->addressCache->bump();
	}
}
