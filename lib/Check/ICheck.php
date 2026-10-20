<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check;

/**
 * A check: its definition, and (in the implementing class) the code that
 * detects what the definition describes.
 *
 * Definitions must be cheap to build: they are read by the config lexicon,
 * which core loads on requests that read this app's settings.
 */
interface ICheck {
	public function definition(): CheckDefinition;
}
