<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Admin;

use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Db\StatsMapper;
use OCA\IntrusionDetection\Definition\Category;
use OCA\IntrusionDetection\Definition\CheckDefinition;
use OCA\IntrusionDetection\Detection\DetectionTotals;
use OCA\IntrusionDetection\Explain\CheckPresenter;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IL10N;

/**
 * The checks of the admin page: every configurable check the registry
 * holds, presented with its texts and settings, plus how often it fired
 * in the last days. The counts come from the hourly totals and the blocks,
 * two queries for the whole list.
 *
 * @psalm-import-type IntrusionDetectionCheck from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionCheckList from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionCheckStats from ResponseDefinitions
 */
class CheckList {
	/** The badge counts this many days */
	public const BADGE_DAYS = 7;

	public function __construct(
		private readonly CheckRegistry $registry,
		private readonly CheckPresenter $presenter,
		private readonly DetectionTotals $totals,
		private readonly StatsMapper $stats,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * @return IntrusionDetectionCheckList
	 */
	public function all(IL10N $l): array {
		[$counts, $blocked] = $this->counts();
		$checks = [];
		$used = [];
		foreach ($this->registry->configurable() as $check) {
			$checks[] = $this->withStats($check, $l, $counts, $blocked);
			$used[$check->category->value] = true;
		}
		$categories = [];
		foreach (Category::cases() as $category) {
			if (isset($used[$category->value])) {
				$categories[] = ['id' => $category->value, 'name' => $category->label($l)];
			}
		}
		return ['checks' => $checks, 'categories' => $categories];
	}

	/**
	 * @return IntrusionDetectionCheck
	 */
	public function one(CheckDefinition $check, IL10N $l): array {
		[$counts, $blocked] = $this->counts();
		return $this->withStats($check, $l, $counts, $blocked);
	}

	/**
	 * @param array<string, array{enforced: int, observed: int}> $counts
	 * @param array<string, int> $blocked
	 * @return IntrusionDetectionCheck
	 */
	private function withStats(CheckDefinition $check, IL10N $l, array $counts, array $blocked): array {
		$count = $counts[$check->id] ?? ['enforced' => 0, 'observed' => 0];
		$presented = $this->presenter->present($check, $l);
		$presented['stats'] = [
			'days' => self::BADGE_DAYS,
			'detections' => $count['enforced'] + $count['observed'],
			'enforced' => $count['enforced'],
			'observed' => $count['observed'],
			'addressesBlocked' => $blocked[$check->id] ?? 0,
		];
		return $presented;
	}

	/**
	 * @return array{0: array<string, array{enforced: int, observed: int}>, 1: array<string, int>}
	 */
	private function counts(): array {
		$since = $this->timeFactory->getTime() - self::BADGE_DAYS * 86400;
		return [$this->totals->perCheck($since), $this->stats->bansCreatedByCheck($since)];
	}
}
