<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Db;

/**
 * The owner of a table, which deletes (or ends) what it keeps past its own
 * retention. The cleanup job runs every owner in
 * {@see \OCA\IntrusionDetection\BackgroundJob\Cleanup::PURGES}.
 */
interface IPurges {
	/**
	 * @return int how many rows were deleted or ended
	 */
	public function purge(int $now): int;
}
