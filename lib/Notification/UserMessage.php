<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Notification;

/**
 * What a user is told about a detection, in plain text, in their language:
 * what happened, when and from where, what Nextcloud did, and what to do.
 */
final class UserMessage {
	/**
	 * @param list<string> $happened
	 * @param list<string> $done
	 * @param list<string> $advice
	 */
	public function __construct(
		public readonly string $subject,
		public readonly array $happened,
		public readonly string $when,
		public readonly array $done,
		public readonly array $advice,
		public readonly string $language,
	) {
	}

	/**
	 * Everything in one paragraph, for the notification.
	 */
	public function text(): string {
		return implode(' ', array_merge($this->happened, [$this->when], $this->done, $this->advice));
	}
}
