<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Blocklist;

use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCP\IAppConfig;

/**
 * The per-list state, in the app config value `blocklist_state`.
 *
 * Switching a list to a new version is one write of this value, so readers
 * switch from the complete old version to the complete new one at once.
 * Writers hold the sync lock ({@see BlocklistSync}) and reload the value
 * before changing it, so a long-running process cannot write back stale
 * states of other lists.
 */
class StateStore {
	public function __construct(
		private readonly Settings $settings,
		private readonly IAppConfig $appConfig,
	) {
	}

	/**
	 * @return array<string, ListState>
	 */
	public function all(): array {
		$states = [];
		foreach ($this->settings->getJson(GlobalSettings::BLOCKLIST_STATE) as $id => $data) {
			if (is_string($id) && is_array($data)) {
				$states[$id] = ListState::fromArray($data);
			}
		}
		return $states;
	}

	public function get(string $id): ListState {
		return $this->all()[$id] ?? new ListState();
	}

	/**
	 * Re-read the stored states, dropping what this process cached.
	 */
	public function reload(): void {
		$this->appConfig->clearCache();
	}

	/**
	 * Write one list's state. The caller holds the sync lock and reloaded first.
	 */
	public function save(string $id, ListState $state): void {
		$all = $this->all();
		$all[$id] = $state;
		$this->write($all);
	}

	public function remove(string $id): void {
		$all = $this->all();
		if (isset($all[$id])) {
			unset($all[$id]);
			$this->write($all);
		}
	}

	/**
	 * @param array<string, ListState> $states
	 */
	private function write(array $states): void {
		$data = array_map(static fn (ListState $s): array => $s->toArray(), $states);
		$this->settings->setGlobal(GlobalSettings::BLOCKLIST_STATE, $data === [] ? '{}' : json_encode($data, JSON_UNESCAPED_SLASHES));
	}
}
