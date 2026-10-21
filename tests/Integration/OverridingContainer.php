<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCP\Server;
use Psr\Container\ContainerInterface;

/**
 * The server container, with some services replaced for one test.
 */
class OverridingContainer implements ContainerInterface {
	/**
	 * @param array<string, object> $overrides
	 */
	public function __construct(
		private readonly array $overrides,
	) {
	}

	public function get(string $id): mixed {
		return $this->overrides[$id] ?? Server::get($id);
	}

	public function has(string $id): bool {
		return isset($this->overrides[$id]) || Server::get(ContainerInterface::class)->has($id);
	}
}
