<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Lockdown;

use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\Lockdown;
use OCA\IntrusionDetection\Db\LockdownMapper;
use OCA\IntrusionDetection\Notification\LockdownNotices;
use OCP\AppFramework\Utility\ITimeFactory;
use Psr\Log\LoggerInterface;

/**
 * Starts, extends and ends lockdown mode (concept section 11.14): "we are
 * under attack right now".
 *
 * - A lockdown lasts 1 to 24 hours. It can be extended up to 24 hours from
 *   now and ended early, and it ends by itself ({@see self::expireIfDue()}).
 * - A distributed credential stuffing attack starts one for 2 hours when
 *   `lockdown_auto_on_distributed` is on.
 * - The state is kept in the app config, so every effect reads it without a
 *   query; every lockdown is also kept in the history (ids_lockdowns).
 * - Every administrator is notified at the start and the end, and every
 *   change is written to the audit log with who made it.
 *
 * The admin page and occ never depend on anything a lockdown blocks, so a
 * lockdown can always be ended.
 */
class LockdownService {
	/** How long a lockdown started by a distributed attack lasts */
	public const AUTO_DURATION = 7200;

	public function __construct(
		private readonly LockdownState $state,
		private readonly Settings $settings,
		private readonly LockdownMapper $mapper,
		private readonly LockdownNotices $notices,
		private readonly ITimeFactory $timeFactory,
		private readonly AuditLogger $audit,
		private readonly LoggerInterface $logger,
	) {
	}

	/**
	 * Start a lockdown.
	 *
	 * @param list<string>|null $effects the effects to switch on for it; null keeps the configured ones
	 * @throws \InvalidArgumentException for a duration outside 1 to 24 hours, unknown effects or a reason that is too long
	 * @throws LockdownException when a lockdown is already running
	 */
	public function start(int $duration, string $reason, string $actor, ?array $effects = null, ?int $detectionId = null): Lockdown {
		if ($duration < LockdownEffect::MIN_DURATION || $duration > LockdownEffect::MAX_DURATION) {
			throw new \InvalidArgumentException('A lockdown lasts 1 to 24 hours');
		}
		$reason = self::cleanReason($reason);
		if ($this->state->isActive()) {
			throw new LockdownException('A lockdown is already running');
		}
		if ($effects !== null) {
			// Validated like every setting; unknown effects throw.
			$this->settings->setGlobal(GlobalSettings::LOCKDOWN_EFFECTS, array_values(array_unique($effects)));
		}
		$now = $this->timeFactory->getTime();
		$lockdown = new Lockdown();
		$lockdown->setStartedAt($now);
		$lockdown->setPlannedEnd($now + $duration);
		$lockdown->setStartedBy($actor);
		$lockdown->setReason($reason === '' ? null : $reason);
		$lockdown->setEffects(implode(',', array_map(static fn (LockdownEffect $e): string => $e->value, $this->state->effects())));
		$lockdown->setDetectionId($detectionId);
		$lockdown = $this->mapper->insert($lockdown);

		$this->settings->setGlobal(GlobalSettings::LOCKDOWN_ID, $lockdown->getId());
		$this->settings->setGlobal(GlobalSettings::LOCKDOWN_STARTED_AT, $now);
		$this->settings->setGlobal(GlobalSettings::LOCKDOWN_STARTED_BY, $actor);
		$this->settings->setGlobal(GlobalSettings::LOCKDOWN_REASON, $reason);
		// Last: from here on the effects apply.
		$this->settings->setGlobal(GlobalSettings::LOCKDOWN_UNTIL, $now + $duration);

		$this->audit->log('lockdown started by %s until %s (%s), effects: %s', [
			'actor' => $actor,
			'until' => gmdate('c', $now + $duration),
			'reason' => $reason,
			'effects' => (string)$lockdown->getEffects(),
		]);
		$this->notify(fn () => $this->notices->started($lockdown));
		return $lockdown;
	}

	/**
	 * Extend the running lockdown, at most to 24 hours from now.
	 *
	 * @throws \InvalidArgumentException for less than an hour or more than 24
	 * @throws LockdownException when no lockdown is running
	 * @return int the new end
	 */
	public function extend(int $by, string $actor): int {
		if ($by < LockdownEffect::MIN_DURATION || $by > LockdownEffect::MAX_DURATION) {
			throw new \InvalidArgumentException('A lockdown is extended by 1 to 24 hours');
		}
		if (!$this->state->isActive()) {
			throw new LockdownException('No lockdown is running');
		}
		$until = min($this->state->until() + $by, $this->timeFactory->getTime() + LockdownEffect::MAX_DURATION);
		$this->moveEnd($until);
		$this->audit->log('lockdown extended by %s until %s', ['actor' => $actor, 'until' => gmdate('c', $until)]);
		return $until;
	}

	/**
	 * End the running lockdown now (also one that waits for the background
	 * job to clean it up).
	 *
	 * @return bool whether a lockdown was running
	 */
	public function end(string $actor): bool {
		if ($this->state->until() === 0) {
			return false;
		}
		$this->finish($actor, $this->timeFactory->getTime());
		$this->audit->log('lockdown ended by %s', ['actor' => $actor]);
		return true;
	}

	/**
	 * Called by the background job: a lockdown whose time is up ends, and
	 * the administrators are told.
	 *
	 * @return bool whether a lockdown ended just now
	 */
	public function expireIfDue(): bool {
		$until = $this->state->until();
		if ($until === 0 || $until > $this->timeFactory->getTime()) {
			return false;
		}
		$this->finish(Lockdown::ACTOR_AUTOMATIC, $until);
		$this->audit->log('lockdown ended automatically at %s', ['until' => gmdate('c', $until)]);
		return true;
	}

	/**
	 * A distributed credential stuffing attack was detected: start a
	 * lockdown for AUTO_DURATION when that is switched on. A running
	 * lockdown that would end sooner is extended to that long.
	 *
	 * @return bool whether this started or extended a lockdown
	 */
	public function startAutomatically(?int $detectionId, string $reason): bool {
		if (!$this->settings->getBool(GlobalSettings::LOCKDOWN_AUTO_ON_DISTRIBUTED) || !$this->settings->isEnabled()) {
			return false;
		}
		$now = $this->timeFactory->getTime();
		if ($this->state->isActive()) {
			if ($this->state->until() >= $now + self::AUTO_DURATION) {
				return false;
			}
			$this->moveEnd($now + self::AUTO_DURATION);
			$this->audit->log('lockdown extended automatically until %s: %s', ['until' => gmdate('c', $now + self::AUTO_DURATION), 'reason' => self::cleanReason($reason)]);
			return true;
		}
		$this->start(self::AUTO_DURATION, $reason, Lockdown::ACTOR_AUTOMATIC, null, $detectionId);
		return true;
	}

	/**
	 * The running lockdown's history entry.
	 */
	public function current(): ?Lockdown {
		$id = $this->settings->getInt(GlobalSettings::LOCKDOWN_ID);
		return $id === 0 ? null : $this->mapper->findById($id);
	}

	/**
	 * @return list<Lockdown> the latest lockdowns, newest first
	 */
	public function history(int $limit): array {
		return $this->mapper->latest($limit);
	}

	/**
	 * A reason as it is stored: control characters replaced, trimmed, at most MAX_REASON bytes.
	 */
	public static function cleanReason(string $reason): string {
		$reason = trim((string)preg_replace('/[\x00-\x1f\x7f]+/', ' ', $reason));
		return mb_strcut($reason, 0, LockdownEffect::MAX_REASON, 'UTF-8');
	}

	private function moveEnd(int $until): void {
		$this->settings->setGlobal(GlobalSettings::LOCKDOWN_UNTIL, $until);
		$lockdown = $this->current();
		if ($lockdown !== null) {
			$lockdown->setPlannedEnd($until);
			$this->mapper->update($lockdown);
		}
	}

	private function finish(string $actor, int $endedAt): void {
		$lockdown = $this->current();
		$this->settings->setGlobal(GlobalSettings::LOCKDOWN_UNTIL, 0);
		$this->settings->setGlobal(GlobalSettings::LOCKDOWN_ID, 0);
		$this->settings->setGlobal(GlobalSettings::LOCKDOWN_STARTED_AT, 0);
		$this->settings->setGlobal(GlobalSettings::LOCKDOWN_STARTED_BY, '');
		$this->settings->setGlobal(GlobalSettings::LOCKDOWN_REASON, '');
		if ($lockdown === null) {
			return;
		}
		$lockdown->setEndedAt(min($endedAt, max($lockdown->getPlannedEnd(), $lockdown->getStartedAt())));
		$lockdown->setEndedBy($actor);
		$this->mapper->update($lockdown);
		$this->notify(fn () => $this->notices->ended($lockdown));
	}

	/**
	 * @param \Closure(): int $send
	 */
	private function notify(\Closure $send): void {
		try {
			$send();
		} catch (\Throwable $e) {
			// The lockdown itself stands; only telling the administrators failed.
			$this->logger->error('Intrusion detection could not notify the administrators about a lockdown', ['exception' => $e]);
		}
	}
}
