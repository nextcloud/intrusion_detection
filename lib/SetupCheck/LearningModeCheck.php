<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SetupCheck;

use OCA\IntrusionDetection\Learning\LearningService;
use OCA\IntrusionDetection\Notification\AdminLinks;
use OCA\IntrusionDetection\State\AppState;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IL10N;

/**
 * Learning mode has been running for more than 14 days, which only happens
 * when an administrator extended it: checks set to Protect still only observe.
 */
class LearningModeCheck extends ProblemCheck {
	public const DAYS = 14;

	public function __construct(
		IL10N $l,
		AdminLinks $links,
		private readonly LearningService $learning,
		private readonly ITimeFactory $timeFactory,
		private readonly AppState $state,
	) {
		parent::__construct($l, $links);
	}

	#[\Override]
	public function getName(): string {
		return $this->l->t('Intrusion detection: learning mode');
	}

	#[\Override]
	protected function fine(): string {
		return $this->l->t('Learning mode is not running for longer than planned.');
	}

	#[\Override]
	public function finding(IL10N $l): ?Finding {
		if (!$this->learning->isActive()) {
			return null;
		}
		$started = $this->state->getInt(LearningService::STARTED_STATE);
		if ($started === 0) {
			$started = $this->state->getInt(AppState::INSTALLED_AT);
		}
		$days = intdiv($this->timeFactory->getTime() - $started, 86400);
		if ($started === 0 || $days < self::DAYS) {
			return null;
		}
		return new Finding(
			'learning_long',
			Finding::LEVEL_INFO,
			$l->t('Learning mode is still on'),
			$l->n('Learning mode has been on for %n day.', 'Learning mode has been on for %n days.', $days) . ' ' . $l->t('Checks set to Protect only record what they would block; earlier blocks, blocks you add by hand, a user\'s "No, it was not me", decoys and reserved names still block.'),
			$l->t('Look through the recent detections. If they show no false alarms, start protecting.'),
			'#settings-learning',
			$l->t('Open learning mode'),
		);
	}
}
