<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check;

use OCP\IL10N;

/**
 * Something a check needs from the server before it can run.
 */
enum Requirement: string {
	/** APCu, Redis or Memcached as a local or distributed cache */
	case MemoryCache = 'memory_cache';
	/** A working mail configuration */
	case Mail = 'mail';

	public function describe(IL10N $l): string {
		return match ($this) {
			self::MemoryCache => $l->t('Needs a memory cache (APCu, Redis or Memcached). Counting in the database would cost a write on every request.'),
			self::Mail => $l->t('Needs email to be configured.'),
		};
	}
}
