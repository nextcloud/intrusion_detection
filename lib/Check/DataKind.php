<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check;

/**
 * The kinds of data checks store. The Data and privacy tab explains each one:
 * what it is, why it is kept, and for how long.
 */
enum DataKind: string {
	case FailedAttempts = 'failed_attempts';
	case SuccessfulLogins = 'successful_logins';
	case Detections = 'detections';
	case Bans = 'bans';
	case Flags = 'flags';
	case LoginHistory = 'login_history';
	case SecurityChanges = 'security_changes';
	case KnownDevices = 'known_devices';
	case TokenOrigins = 'token_origins';
	case Decoys = 'decoys';
	case BlocklistRanges = 'blocklist_ranges';
	case RequestExcerpts = 'request_excerpts';
	case CacheCounters = 'cache_counters';
	/** Small per-account values, such as when the password was last checked against breach lists */
	case AccountState = 'account_state';
	case ConfigSnapshot = 'config_snapshot';
	case Approvals = 'approvals';
	/** Networks users confirmed as their own */
	case TrustedNetworks = 'trusted_networks';
	/** Keyed fingerprints of sessions whose login waits for its confirmation */
	case UnconfirmedSessions = 'unconfirmed_sessions';
	/** One-time links that let the previous email address lock an account */
	case LockLinks = 'lock_links';
	/** Progress of a user through the "Secure my account" checklist */
	case SecureAccountProgress = 'secure_account_progress';
}
