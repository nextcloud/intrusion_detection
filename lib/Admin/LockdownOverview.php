<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Admin;

use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Confirm\ConfirmationCoverage;
use OCA\IntrusionDetection\Db\Lockdown;
use OCA\IntrusionDetection\Lockdown\LockdownEffect;
use OCA\IntrusionDetection\Lockdown\LockdownService;
use OCA\IntrusionDetection\Lockdown\LockdownState;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\IL10N;

/**
 * Lockdown mode as the admin page shows it (concept sections 11.14 and
 * 16.1): whether it is on, until when, who started it and why, its effects
 * with their switches, how many accounts could not log in with their
 * password during it, and the latest lockdowns. It also puts the lockdown
 * into the status banner and the dashboard widget, as a status contributor.
 *
 * @psalm-import-type IntrusionDetectionLockdown from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionLockdownEntry from ResponseDefinitions
 * @psalm-import-type IntrusionDetectionProblem from ResponseDefinitions
 */
class LockdownOverview implements IStatusContributor {
	public const KEY = 'lockdown';
	public const HISTORY = 10;

	public function __construct(
		private readonly LockdownState $state,
		private readonly LockdownService $service,
		private readonly Settings $settings,
		private readonly ConfirmationCoverage $coverage,
	) {
	}

	/**
	 * @return IntrusionDetectionLockdown
	 */
	public function get(IL10N $l, bool $withHistory = true): array {
		$info = $this->state->info();
		return [
			'active' => $info['active'],
			'until' => $info['until'],
			'startedAt' => $info['startedAt'],
			'startedBy' => $info['startedBy'],
			'reason' => $info['reason'],
			'automatic' => $info['startedBy'] === Lockdown::ACTOR_AUTOMATIC,
			'effects' => array_map(static fn (LockdownEffect $effect): array => [
				'id' => $effect->value,
				'label' => $effect->label($l),
				'description' => $effect->description($l),
				'enabled' => in_array($effect->value, $info['effects'], true),
			], LockdownEffect::cases()),
			'defaultDuration' => $this->settings->getInt(GlobalSettings::LOCKDOWN_DEFAULT_DURATION),
			'minDuration' => LockdownEffect::MIN_DURATION,
			'maxDuration' => LockdownEffect::MAX_DURATION,
			'maxReason' => LockdownEffect::MAX_REASON,
			'usersWithoutMethod' => $this->coverage->users()['withoutMethod'],
			'history' => $withHistory ? array_map(self::entry(...), $this->service->history(self::HISTORY)) : [],
		];
	}

	#[\Override]
	public function key(): string {
		return self::KEY;
	}

	/**
	 * Only while a lockdown is on, so that the status stays as cheap as before otherwise.
	 */
	#[\Override]
	public function data(IL10N $l): ?array {
		if (!$this->state->isActive()) {
			return null;
		}
		$info = $this->state->info();
		return [
			'active' => true,
			'until' => $info['until'],
			'startedAt' => $info['startedAt'],
			'startedBy' => $info['startedBy'],
			'reason' => $info['reason'],
			'automatic' => $info['startedBy'] === Lockdown::ACTOR_AUTOMATIC,
			'effects' => $info['effects'],
		];
	}

	#[\Override]
	public function problems(IL10N $l): array {
		return [];
	}

	/**
	 * @return IntrusionDetectionLockdownEntry
	 */
	public static function entry(Lockdown $lockdown): array {
		return [
			'id' => (int)$lockdown->getId(),
			'startedAt' => $lockdown->getStartedAt(),
			'until' => $lockdown->getPlannedEnd(),
			'endedAt' => $lockdown->getEndedAt(),
			'startedBy' => $lockdown->getStartedBy(),
			'endedBy' => $lockdown->getEndedBy(),
			'reason' => (string)$lockdown->getReason(),
			'effects' => $lockdown->getEffectList(),
			'automatic' => $lockdown->getStartedBy() === Lockdown::ACTOR_AUTOMATIC,
		];
	}
}
