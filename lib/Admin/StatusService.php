<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Admin;

use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Config\Prerequisites;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Db\StatsMapper;
use OCA\IntrusionDetection\Learning\LearningService;
use OCA\IntrusionDetection\Perf\GuardTimer;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IL10N;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * What intrusion detection is doing right now: the state, the last 24 hours
 * in numbers, the prerequisites and the measured cost. Shown in the status
 * banner of the admin page, in the dashboard widget and by occ.
 *
 * @psalm-import-type IntrusionDetectionStatus from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionLearning from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionProblem from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionCategoryCount from ResponseDefinitions
 */
class StatusService {
	/** @var list<class-string<IStatusContributor>> */
	public const CONTRIBUTORS = [
		SetupProblems::class,
	];

	public const STATE_PROTECTING = 'protecting';
	public const STATE_LEARNING = 'learning';
	public const STATE_OFF = 'off';

	/** Above this average guard time the banner points to the likely cause */
	public const SLOW_GUARD_MICROSECONDS = 1000;

	public function __construct(
		private readonly Settings $settings,
		private readonly CheckRegistry $registry,
		private readonly CheckNames $names,
		private readonly LearningService $learning,
		private readonly Prerequisites $prerequisites,
		private readonly BanMapper $bans,
		private readonly DetectionMapper $detections,
		private readonly StatsMapper $stats,
		private readonly GuardTimer $timer,
		private readonly ITimeFactory $timeFactory,
		private readonly ContainerInterface $container,
		private readonly LoggerInterface $logger,
	) {
	}

	/**
	 * @return 'protecting'|'learning'|'off'
	 */
	public function state(): string {
		if (!$this->settings->isEnabled()) {
			return self::STATE_OFF;
		}
		return $this->learning->isActive() ? self::STATE_LEARNING : self::STATE_PROTECTING;
	}

	/**
	 * @return IntrusionDetectionLearning
	 */
	public function learning(): array {
		$until = $this->learning->until();
		$active = $this->learning->isActive();
		return [
			'active' => $active,
			'until' => $active ? $until : 0,
			'daysLeft' => $active ? $this->learning->daysLeft() : 0,
			'minDays' => LearningService::MIN_DAYS,
			'maxDays' => LearningService::MAX_DAYS,
		];
	}

	/**
	 * @return IntrusionDetectionStatus
	 */
	public function status(IL10N $l): array {
		$now = $this->timeFactory->getTime();
		$since = $now - 86400;

		$modes = ['protect' => 0, 'observe' => 0, 'off' => 0];
		foreach ($this->registry->configurable() as $check) {
			$modes[$this->settings->effectiveMode($check->id)->value]++;
		}

		$enforced = 0;
		$observed = 0;
		/** @var array<string, IntrusionDetectionCategoryCount> $categories */
		$categories = [];
		foreach ($this->detections->countByCheck($since) as $checkId => $counts) {
			$enforced += $counts['enforced'];
			$observed += $counts['observed'];
			$category = $this->names->category($checkId);
			$categories[$category->value] ??= ['id' => $category->value, 'name' => $category->label($l), 'enforced' => 0, 'observed' => 0];
			$categories[$category->value]['enforced'] += $counts['enforced'];
			$categories[$category->value]['observed'] += $counts['observed'];
		}

		$cost = $this->timer->summary();
		$problems = [];
		if ($cost !== null && $cost['averageMicroseconds'] > self::SLOW_GUARD_MICROSECONDS) {
			$problems[] = $this->slowGuardsProblem($l);
		}

		$extensions = [];
		foreach (static::CONTRIBUTORS as $class) {
			try {
				$contributor = $this->container->get($class);
				if (!$contributor instanceof IStatusContributor) {
					continue;
				}
				$data = $contributor->data($l);
				if ($data !== null) {
					$extensions[$contributor->key()] = $data;
				}
				array_push($problems, ...$contributor->problems($l));
			} catch (\Throwable $e) {
				// One broken contributor must not take the status page down with it.
				$this->logger->error('Intrusion detection status contributor {class} failed', ['class' => $class, 'exception' => $e]);
			}
		}

		return [
			'state' => $this->state(),
			'learning' => $this->learning(),
			'checks' => $modes,
			'last24h' => [
				'detections' => $enforced + $observed,
				'enforced' => $enforced,
				'observed' => $observed,
				'blockedAddresses' => $this->stats->bansCreatedSince($since),
				'wouldHaveBlocked' => $this->stats->wouldHaveBlockedSince($since),
				'accounts' => $this->stats->accountsSince($since),
				'categories' => array_values($categories),
			],
			'activeBans' => $this->bans->countActive($now),
			'prerequisites' => [
				'memoryCache' => $this->prerequisites->hasDistributedCache() ? 'distributed' : ($this->prerequisites->hasMemoryCache() ? 'local' : 'none'),
				'mail' => $this->prerequisites->hasMail(),
			],
			'cost' => $cost === null ? null : [
				'samples' => $cost['samples'],
				'averageMicroseconds' => round($cost['averageMicroseconds'], 1),
				'maxMicroseconds' => $cost['maxMicroseconds'],
			],
			'costSampleRate' => GuardTimer::SAMPLE_RATE,
			'problems' => $problems,
			'extensions' => $extensions,
		];
	}

	/**
	 * @return IntrusionDetectionProblem
	 */
	private function slowGuardsProblem(IL10N $l): array {
		return [
			'id' => 'slow_guards',
			'level' => 'warning',
			'title' => $l->t('The address check is slower than expected'),
			'text' => $l->t('On average it takes more than 1 ms per request. A local cache shared by many web servers, many blocks or several enabled blocklists make the check slower when its cache is cold. A distributed cache such as Redis helps most.'),
			'url' => null,
			'urlLabel' => null,
		];
	}
}
