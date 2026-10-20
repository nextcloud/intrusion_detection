<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Config;

use OCA\IntrusionDetection\Check\Requirement;
use OCP\ICacheFactory;
use OCP\IConfig;

/**
 * Answers whether the server offers what a check needs.
 */
class Prerequisites {
	public function __construct(
		private readonly ICacheFactory $cacheFactory,
		private readonly IConfig $config,
	) {
	}

	public function isMet(Requirement $requirement): bool {
		return match ($requirement) {
			Requirement::MemoryCache => $this->hasMemoryCache(),
			Requirement::Mail => $this->hasMail(),
		};
	}

	public function hasMemoryCache(): bool {
		return $this->cacheFactory->isAvailable() || $this->cacheFactory->isLocalCacheAvailable();
	}

	public function hasDistributedCache(): bool {
		return $this->cacheFactory->isAvailable();
	}

	public function hasMail(): bool {
		// Without an SMTP or sendmail mode Nextcloud falls back to PHP's mail(),
		// which is configured when the admin set a sender address.
		return $this->config->getSystemValueString('mail_smtpmode', '') !== ''
			|| $this->config->getSystemValueString('mail_from_address', '') !== '';
	}
}
