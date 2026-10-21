<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Blocklist;

/**
 * The next contribution: the exact payload, the window it covers, and why it
 * would not be sent, if it would not.
 *
 * @psalm-type Report = array{ip: string, check: string, first_seen: int, hits: int}
 * @psalm-type Payload = array{instance: string, version: int, reports: list<Report>}
 */
final class ContributionBatch {
	/** config.php does not make the feature available: nothing is built */
	public const REASON_UNAVAILABLE = 'unavailable';
	public const REASON_DISABLED = 'disabled';
	/** The app's master switch is off */
	public const REASON_PROTECTION_OFF = 'protection_off';
	public const REASON_NO_URL = 'no_url';
	public const REASON_URL_REFUSED = 'url_refused';
	public const REASON_NOTHING_NEW = 'nothing_new';

	/**
	 * @param ?Payload $payload null only when the feature is unavailable
	 * @param ?string $reason one of the REASON_* constants, null when it would be sent
	 * @param bool $truncated more reports were due than one run sends
	 */
	public function __construct(
		public readonly ?array $payload,
		public readonly ?string $reason,
		public readonly int $windowStart,
		public readonly int $windowEnd,
		public readonly bool $truncated = false,
	) {
	}

	public function wouldSend(): bool {
		return $this->reason === null;
	}

	/**
	 * The request body exactly as it is sent.
	 */
	public function body(): string {
		return $this->payload === null ? '' : json_encode($this->payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
	}
}
