<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Admin;

use OCA\IntrusionDetection\Check\Category;
use OCA\IntrusionDetection\Check\CheckDefinition;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Db\StatsMapper;
use OCA\IntrusionDetection\Explain\CheckPresenter;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IL10N;

/**
 * The check cards of the admin page: every configurable check the registry
 * holds, presented with its texts and settings, plus what it did in the
 * last days for the badge.
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
		private readonly DetectionMapper $detections,
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
	 * @param array<string, array{enforced: int, observed: int, hits: int}> $counts
	 * @param array<string, int> $blocked
	 * @return IntrusionDetectionCheck
	 */
	private function withStats(CheckDefinition $check, IL10N $l, array $counts, array $blocked): array {
		$count = $counts[$check->id] ?? ['enforced' => 0, 'observed' => 0, 'hits' => 0];
		$presented = $this->presenter->present($check, $l);
		$presented['stats'] = [
			'days' => self::BADGE_DAYS,
			'detections' => $count['enforced'] + $count['observed'],
			'enforced' => $count['enforced'],
			'observed' => $count['observed'],
			'fired' => $count['hits'],
			'addressesBlocked' => $blocked[$check->id] ?? 0,
		];
		return $presented;
	}

	/**
	 * @return array{0: array<string, array{enforced: int, observed: int, hits: int}>, 1: array<string, int>}
	 */
	private function counts(): array {
		$since = $this->timeFactory->getTime() - self::BADGE_DAYS * 86400;
		return [$this->detections->countByCheck($since), $this->stats->bansCreatedByCheck($since)];
	}
}
