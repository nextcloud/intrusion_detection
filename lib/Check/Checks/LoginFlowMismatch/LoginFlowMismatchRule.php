<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\LoginFlowMismatch;

/**
 * Why a login flow mismatch detection fired, as stored in its facts.
 */
enum LoginFlowMismatchRule: string {
	/** Started from an address that was blocked */
	case InitiatorBlocked = 'initiator_blocked';
	/** Started from an address that was marked as attacking */
	case InitiatorFlagged = 'initiator_flagged';
	/** Approved from another network */
	case OtherNetwork = 'other_network';
	/** Approved too long after it was started */
	case TooOld = 'too_old';
	/** Started and approved over different IP families */
	case OtherFamily = 'other_family';
}
