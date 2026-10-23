<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Blocklist\Parser;

/**
 * Reads the ranges of one list format.
 */
interface IListParser {
	/**
	 * @param int $maxEntries the most valid ranges the list may have
	 * @throws ListFormatException when the file as a whole is not in this format
	 * @throws ListTooLongException as soon as the list has more than `$maxEntries` ranges
	 */
	public function parse(string $body, int $maxEntries = PHP_INT_MAX): ParsedList;
}
