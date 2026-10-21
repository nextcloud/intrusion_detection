<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\AdminChange;

use OC\Settings\AuthorizedGroupMapper;
use Psr\Log\LoggerInterface;

/**
 * Groups that administrators gave parts of the administration settings to
 * (Administration settings → Administration privileges). The settings app
 * stores each delegation as a row of group id and settings class in
 * `authorized_groups`; joining such a group grants administration rights.
 */
class DelegatedGroups {
	/** @var array<string, list<string>>|null */
	private ?array $delegations = null;

	public function __construct(
		private readonly AuthorizedGroupMapper $mapper,
		private readonly LoggerInterface $logger,
	) {
	}

	/**
	 * @return array<string, list<string>> group id => short names of the delegated settings classes, sorted
	 */
	public function all(): array {
		if ($this->delegations === null) {
			$delegations = [];
			try {
				foreach ($this->mapper->findAll() as $row) {
					$class = $row->getClass();
					$delegations[$row->getGroupId()][] = substr($class, (int)strrpos('\\' . $class, '\\'));
				}
			} catch (\Throwable $e) {
				$this->logger->error('Intrusion detection could not read the delegated administration settings', ['exception' => $e]);
			}
			foreach ($delegations as $gid => $classes) {
				$classes = array_values(array_unique($classes));
				sort($classes);
				$delegations[$gid] = $classes;
			}
			ksort($delegations);
			$this->delegations = $delegations;
		}
		return $this->delegations;
	}

	/**
	 * @return ?list<string> the delegated settings of a group, or null when it has none
	 */
	public function of(string $gid): ?array {
		return $this->all()[$gid] ?? null;
	}
}
