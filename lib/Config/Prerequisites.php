<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Config;

use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Definition\Requirement;
use OCP\IConfig;

/**
 * Answers whether the server offers what a check needs.
 */
class Prerequisites {
	public function __construct(
		private readonly Caches $caches,
		private readonly IConfig $config,
		private readonly CoreHooks $hooks,
	) {
	}

	public function isMet(Requirement $requirement): bool {
		return match ($requirement) {
			Requirement::MemoryCache => $this->caches->isAvailable(),
			Requirement::Mail => $this->hasMail(),
			Requirement::RequestGuards => $this->hooks->has(CoreHooks::REQUEST_GUARDS),
			Requirement::ShareAccessEvent => $this->hooks->has(CoreHooks::SHARE_ACCESS_EVENT),
			Requirement::ResetEvent => $this->hooks->has(CoreHooks::RESET_EVENT),
			Requirement::LoginFlowEvent => $this->hooks->has(CoreHooks::LOGIN_FLOW_EVENT),
		};
	}

	public function hasMail(): bool {
		// Without an SMTP or sendmail mode Nextcloud falls back to PHP's mail(),
		// which is configured when the admin set a sender address.
		return $this->config->getSystemValueString('mail_smtpmode', '') !== ''
			|| $this->config->getSystemValueString('mail_from_address', '') !== '';
	}
}
