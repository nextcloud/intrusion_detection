<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Incident;

/**
 * A remark on the report as a whole, with an optional link.
 */
final class ReportNote {
	public function __construct(
		public readonly string $id,
		public readonly string $text,
		public readonly ?string $url = null,
		public readonly ?string $linkLabel = null,
	) {
	}

	/**
	 * @return array{id: string, text: string, url: ?string, linkLabel: ?string}
	 */
	public function toArray(): array {
		return ['id' => $this->id, 'text' => $this->text, 'url' => $this->url, 'linkLabel' => $this->linkLabel];
	}
}
