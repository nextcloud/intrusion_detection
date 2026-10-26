<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Response;

use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Definition\CheckDefinition;
use OCA\IntrusionDetection\Detection\DetectionDraft;

final class ResponseContext {
	public function __construct(
		public readonly DetectionDraft $draft,
		public readonly Detection $detection,
		public readonly CheckDefinition $definition,
		/** False for a repeated hit merged into an earlier detection */
		public readonly bool $isNew,
		/** The hits this added to the detection: more than one when its check cooled down before */
		public readonly int $hits = 1,
	) {
	}
}
