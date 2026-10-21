<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check;

use OCP\IL10N;

enum CostClass: string {
	case OnFailureOnly = 'on_failure_only';
	case OnLoginOnly = 'on_login_only';
	case EveryRequestTiny = 'every_request_tiny';
	/** A quick scan of the web address on every request, a closer look only on suspicious ones */
	case EveryRequestScan = 'every_request_scan';
	case ExternalCall = 'external_call';
	case Background = 'background';

	public function describe(IL10N $l): string {
		return match ($this) {
			self::OnFailureOnly => $l->t('Runs only when a login or share access fails. No effect on normal requests.'),
			self::OnLoginOnly => $l->t('Runs once per successful login.'),
			self::EveryRequestTiny => $l->t('Adds one memory-cache lookup to requests. Typically well under 0.1 ms.'),
			self::EveryRequestScan => $l->t('A quick scan of the web address on every request. Only requests that contain suspicious characters are examined further. Typically under 0.01 ms.'),
			self::ExternalCall => $l->t('Contacts an external service.'),
			self::Background => $l->t('Runs in a background job.'),
		};
	}
}
