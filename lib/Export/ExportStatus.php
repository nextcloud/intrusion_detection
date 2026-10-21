<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Export;

/**
 * The firewall export as the admin page and occ intrusion:status show it.
 */
final class ExportStatus {
	/**
	 * @param ?string $directory the configured directory, as written in config.php
	 * @param list<ExportFormat> $formats
	 * @param ?string $error an {@see ExportException} code: why nothing can be written, or why the last write failed
	 */
	public function __construct(
		public readonly ?string $directory,
		public readonly array $formats,
		public readonly ?int $lastWriteAt,
		public readonly ?string $error,
		public readonly ?int $errorAt,
		public readonly int $entries,
	) {
	}

	public function isActive(): bool {
		return $this->directory !== null && $this->formats !== [];
	}

	/**
	 * @return array{directory: ?string, active: bool, formats: list<string>, files: list<string>, lastWriteAt: ?int, error: ?string, errorAt: ?int, entries: int}
	 */
	public function toArray(): array {
		return [
			'directory' => $this->directory,
			'active' => $this->isActive(),
			'formats' => array_map(static fn (ExportFormat $f): string => $f->value, $this->formats),
			'files' => array_map(static fn (ExportFormat $f): string => $f->fileName(), $this->formats),
			'lastWriteAt' => $this->lastWriteAt,
			'error' => $this->error,
			'errorAt' => $this->errorAt,
			'entries' => $this->entries,
		];
	}
}
