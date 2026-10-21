<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Export;

use OCP\IL10N;

/**
 * The export directory cannot be used, or a file could not be written.
 */
class ExportException extends \RuntimeException {
	public const NOT_CONFIGURED = 'not_configured';
	public const NOT_ABSOLUTE = 'not_absolute';
	public const NOT_FOUND = 'not_found';
	public const NOT_A_DIRECTORY = 'not_a_directory';
	public const INSIDE_DATA_DIRECTORY = 'inside_data_directory';
	public const INSIDE_WEB_ROOT = 'inside_web_root';
	public const WORLD_WRITABLE = 'world_writable';
	public const NOT_WRITABLE = 'not_writable';
	public const WRITE_FAILED = 'write_failed';

	public function __construct(
		public readonly string $reason,
	) {
		parent::__construct($reason);
	}

	/**
	 * What is wrong, in plain words, for the admin page.
	 */
	public static function describe(string $reason, IL10N $l): string {
		return match ($reason) {
			self::NOT_CONFIGURED => $l->t('No export directory is set in config.php, so nothing is written.'),
			self::NOT_ABSOLUTE => $l->t('The export directory must be an absolute path.'),
			self::NOT_FOUND => $l->t('The export directory does not exist.'),
			self::NOT_A_DIRECTORY => $l->t('The export directory is not a directory.'),
			self::INSIDE_DATA_DIRECTORY => $l->t('The export directory must not be inside the data directory.'),
			self::INSIDE_WEB_ROOT => $l->t('The export directory must not be inside the Nextcloud installation or an apps directory, nor contain it.'),
			self::WORLD_WRITABLE => $l->t('The export directory must not be writable by every user.'),
			self::NOT_WRITABLE => $l->t('The web server user cannot write to the export directory.'),
			default => $l->t('A file could not be written to the export directory.'),
		};
	}
}
