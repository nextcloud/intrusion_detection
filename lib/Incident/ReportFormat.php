<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Incident;

/**
 * How an incident report is handed out: shown on the admin page, or as a
 * JSON or printable HTML document.
 */
enum ReportFormat: string {
	case Screen = 'screen';
	case Json = 'json';
	case Html = 'html';

	public function contentType(): string {
		return match ($this) {
			self::Html => 'text/html; charset=utf-8',
			default => 'application/json; charset=utf-8',
		};
	}

	public function extension(): string {
		return $this === self::Html ? 'html' : 'json';
	}
}
