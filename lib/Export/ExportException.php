<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Export;

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
}
