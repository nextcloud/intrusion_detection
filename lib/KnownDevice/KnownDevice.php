<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\KnownDevice;

/**
 * One browser a user chose to remember after confirming a login. Only a
 * keyed fingerprint of its cookie is known, never the cookie itself.
 */
final class KnownDevice {
	public function __construct(
		public readonly string $id,
		public readonly string $uid,
		/** Browser family, e.g. "firefox"; see {@see DeviceLabel} */
		public readonly string $family,
		/** Platform family, e.g. "linux" */
		public readonly string $platform,
		/** "Firefox on Linux", in English, for occ and logs */
		public readonly string $label,
		/** The network it was remembered from */
		public readonly ?string $netKey,
		public readonly int $createdAt,
		public readonly int $lastSeenAt,
	) {
	}

	/**
	 * @param array<string, mixed> $row
	 */
	public static function fromRow(array $row): self {
		return new self(
			(string)$row['id'],
			(string)$row['uid'],
			(string)($row['family'] ?? DeviceLabel::OTHER),
			(string)($row['platform'] ?? DeviceLabel::OTHER),
			(string)($row['label'] ?? ''),
			isset($row['net_key']) ? (string)$row['net_key'] : null,
			(int)$row['created_at'],
			(int)$row['last_seen_at'],
		);
	}
}
