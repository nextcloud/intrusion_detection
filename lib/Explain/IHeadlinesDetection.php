<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Explain;

use OCA\IntrusionDetection\Db\Detection;
use OCP\IL10N;

/**
 * A check whose detections are better named by what happened than by the
 * check and the source, e.g. "bob was made an administrator". The headline is
 * the subject of notifications and emails.
 */
interface IHeadlinesDetection {
	/**
	 * @return ?string plain text, or null for the default headline
	 */
	public function headline(Detection $detection, IL10N $l): ?string;
}
