<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Blocklist\Parser;

/**
 * Iterates over the lines of a downloaded file without splitting it into
 * one big array first.
 */
final class Lines {
	/**
	 * @return \Generator<int, string>
	 */
	public static function of(string $body): \Generator {
		$offset = 0;
		$length = strlen($body);
		if (str_starts_with($body, "\xef\xbb\xbf")) {
			$offset = 3;
		}
		while ($offset < $length) {
			$end = strpos($body, "\n", $offset);
			if ($end === false) {
				$end = $length;
			}
			yield rtrim(substr($body, $offset, $end - $offset), "\r");
			$offset = $end + 1;
		}
	}
}
