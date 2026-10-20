<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Detection;

use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Net\SourceKey;

/**
 * One failed attempt as recorded, with the fingerprints detectors compare.
 * The fingerprints are hex strings and must never be logged.
 */
final class AttemptRecord {
	/**
	 * @param list<string> $passwordCandidates the password fingerprints to look for (today's, and yesterday's after midnight)
	 */
	public function __construct(
		public readonly AttemptKind $kind,
		public readonly SourceKey $source,
		public readonly ?string $nameHmac,
		public readonly ?string $uid,
		public readonly ?int $shareId,
		public readonly ?string $passwordFingerprint,
		public readonly array $passwordCandidates,
		public readonly int $time,
		public readonly bool $stored,
	) {
	}
}
