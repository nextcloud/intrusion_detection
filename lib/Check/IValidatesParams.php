<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check;

use OCA\IntrusionDetection\Definition\InvalidParamException;

/**
 * A check with rules for its parameters beyond type and range, for example
 * "a reserved name must not be an existing account". Settings calls it on
 * every write, so the admin page, occ and services validate the same way.
 */
interface IValidatesParams {
	/**
	 * @param int|float|bool|string|list<string> $value the value, already valid for its definition
	 * @return int|float|bool|string|list<string> the value to store (possibly normalised)
	 * @throws InvalidParamException
	 */
	public function validateParam(string $name, int|float|bool|string|array $value): int|float|bool|string|array;
}
