<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Explain;

use OCP\IL10N;

/**
 * A response handler that can say in a sentence what one of its stored actions did.
 */
interface IDescribesAction {
	/**
	 * @param array{type: string, enforced: bool, ref?: mixed, note?: string} $action
	 * @return list<string>
	 */
	public function describeAction(array $action, IL10N $l, DateFormatter $dates): array;
}
