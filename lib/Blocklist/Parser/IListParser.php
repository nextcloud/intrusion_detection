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
	 * @throws ListFormatException when the file as a whole is not in this format
	 */
	public function parse(string $body): ParsedList;
}
