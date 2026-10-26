<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

/**
 * Times work for a performance budget as the fastest of several runs, after
 * one run to warm up. Other load on the machine, such as a shared CI runner
 * or parallel test suites, can only make a run slower, so the fastest run is
 * the one closest to what the work itself costs.
 *
 * Shared GitHub Actions runners are also slower than the machines the budgets
 * are set for, and stay busy for whole runs, so there a budget is doubled. It
 * still catches a regression, which costs several times the budget.
 */
trait FastestRun {
	/**
	 * A performance budget for the machine the tests run on.
	 */
	private static function budget(float $budget): float {
		return getenv('GITHUB_ACTIONS') === 'true' ? 2 * $budget : $budget;
	}

	/**
	 * @param \Closure(): float $measure one run, returning its own measurement
	 * @return float the smallest measurement of the runs after the warm-up
	 */
	private static function fastest(\Closure $measure, int $runs = 5): float {
		$measure();
		$best = INF;
		for ($run = 0; $run < $runs; $run++) {
			$best = min($best, $measure());
		}
		return $best;
	}
}
