<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Explain;

/**
 * What the affected user is told about a detection: a short subject, a few
 * plain-text sentences about what happened, and what the user should do
 * (the notification and the email escape them).
 */
final class UserNotice {
	/**
	 * @param list<string> $message
	 * @param list<string> $advice
	 */
	public function __construct(
		public readonly string $subject,
		public readonly array $message,
		public readonly array $advice = [],
	) {
	}
}
