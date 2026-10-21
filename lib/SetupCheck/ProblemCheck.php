<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SetupCheck;

use OCA\IntrusionDetection\Notification\AdminLinks;
use OCP\IL10N;
use OCP\SetupCheck\ISetupCheck;
use OCP\SetupCheck\SetupResult;

/**
 * A setup check of the app. The same finding is shown in core's setup checks
 * and, through {@see \OCA\IntrusionDetection\Admin\SetupProblems}, as a card
 * with a fix under the status banner of the admin page. Findings run on
 * every view of the status, so they must be cheap.
 */
abstract class ProblemCheck implements ISetupCheck {
	public function __construct(
		protected readonly IL10N $l,
		private readonly AdminLinks $links,
	) {
	}

	/**
	 * The problem, or null when everything is fine.
	 */
	abstract public function finding(IL10N $l): ?Finding;

	/**
	 * What core's setup checks say when there is no problem.
	 */
	abstract protected function fine(): string;

	#[\Override]
	public function getCategory(): string {
		return 'security';
	}

	#[\Override]
	public function run(): SetupResult {
		$finding = $this->finding($this->l);
		if ($finding === null) {
			return SetupResult::success($this->fine());
		}
		$description = $finding->text . ' ' . $finding->fix;
		$url = $finding->url !== null && str_starts_with($finding->url, '#')
			? $this->links->adminPage() . $finding->url
			: $finding->url;
		return match ($finding->level) {
			Finding::LEVEL_ERROR => SetupResult::error($description, $url),
			Finding::LEVEL_WARNING => SetupResult::warning($description, $url),
			default => SetupResult::info($description, $url),
		};
	}
}
