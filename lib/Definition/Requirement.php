<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Definition;

use OCP\IL10N;

/**
 * Something a check needs from the server before it can run.
 */
enum Requirement: string {
	/** APCu, Redis or Memcached as a local or distributed cache */
	case MemoryCache = 'memory_cache';
	/** A working mail configuration */
	case Mail = 'mail';
	/** Nextcloud server checks every request with the app's guards */
	case RequestGuards = 'request_guards';
	/** Nextcloud server tells about failed share link accesses */
	case ShareAccessEvent = 'share_access_event';
	/** Nextcloud server tells about password reset requests */
	case ResetEvent = 'reset_event';
	/** Nextcloud server tells about logins granted through the login flow */
	case LoginFlowEvent = 'login_flow_event';

	public function describe(IL10N $l): string {
		return match ($this) {
			self::MemoryCache => $l->t('Needs a memory cache (APCu, Redis or Memcached). Counting in the database would cost a write on every request.'),
			self::Mail => $l->t('Needs email to be configured.'),
			self::RequestGuards => $l->t('Needs a version of Nextcloud server that lets apps check every request.'),
			self::ShareAccessEvent => $l->t('Needs a version of Nextcloud server that tells apps about failed share link accesses.'),
			self::ResetEvent => $l->t('Needs a version of Nextcloud server that tells apps about password reset requests.'),
			self::LoginFlowEvent => $l->t('Needs a version of Nextcloud server that tells apps about logins granted to apps and clients.'),
		};
	}
}
