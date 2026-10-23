<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Login;

use OCA\IntrusionDetection\Login\SessionIdRenewal;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * The renewal of the session id on a server that has core's API or not, as
 * the test says.
 */
final class FixedSessionIdRenewal extends SessionIdRenewal {
	public function __construct(
		ContainerInterface $container,
		LoggerInterface $logger,
		private readonly bool $available,
	) {
		parent::__construct($container, $logger);
	}

	#[\Override]
	protected function available(): bool {
		return $this->available;
	}
}
