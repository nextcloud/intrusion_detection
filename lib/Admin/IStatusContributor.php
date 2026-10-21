<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Admin;

use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\IL10N;

/**
 * Adds to the status the admin page shows on top and the dashboard widget
 * summarises: a field of its own (for example the lockdown state) and
 * problems shown as cards under the status banner (for example from the
 * setup checks). Implementations are listed in {@see StatusService::CONTRIBUTORS}.
 *
 * Contributors run whenever the status is shown, so they must be cheap.
 *
 * @psalm-import-type IntrusionDetectionProblem from ResponseDefinitions
 */
interface IStatusContributor {
	/**
	 * The key of this contributor's data in the status `extensions`.
	 */
	public function key(): string;

	/**
	 * @return array<string, mixed>|null data for the page, or null for none
	 */
	public function data(IL10N $l): ?array;

	/**
	 * @return list<IntrusionDetectionProblem>
	 */
	public function problems(IL10N $l): array;
}
