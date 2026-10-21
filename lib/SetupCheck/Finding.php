<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SetupCheck;

/**
 * A problem one of the app's setup checks found: shown in core's setup
 * checks and as a card under the status banner of the admin page.
 */
final class Finding {
	public const LEVEL_INFO = 'info';
	public const LEVEL_WARNING = 'warning';
	public const LEVEL_ERROR = 'error';

	/**
	 * @param self::LEVEL_* $level
	 * @param string $text what is wrong and what it means, in plain words
	 * @param string $fix what to do about it
	 * @param ?string $url documentation, or a place on the admin page such as "#decoys"
	 */
	public function __construct(
		public readonly string $id,
		public readonly string $level,
		public readonly string $title,
		public readonly string $text,
		public readonly string $fix,
		public readonly ?string $url = null,
		public readonly ?string $urlLabel = null,
	) {
	}
}
