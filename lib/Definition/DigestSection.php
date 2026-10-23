<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Definition;

/**
 * A section of the administrators' digest that lists a check's detections
 * beyond the per-check counts.
 */
enum DigestSection: string {
	/** The accounts with the most detections */
	case Accounts = 'accounts';
	/** The shares with the most detections */
	case Shares = 'shares';
	/** The decoys that were used, with their label */
	case Decoys = 'decoys';
}
