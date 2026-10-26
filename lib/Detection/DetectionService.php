<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Detection;

use OCA\IntrusionDetection\Cache\KeyLock;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Definition\Severity;
use OCA\IntrusionDetection\Risk\RiskAssessment;
use OCA\IntrusionDetection\Risk\RiskScorer;
use OCP\AppFramework\Utility\ITimeFactory;

/**
 * Stores detections. Repeated hits of the same check and rule from the same
 * source (or for the same user) within the merge window update one row,
 * which keeps the noise of traps and scanners small. The row's facts are
 * merged ({@see FactsMerger}), so it still explains every hit. A merged
 * hit adds to the stored hit count rather than replacing it, together with
 * the hits counted in the memory cache meanwhile ({@see DetectionHits}),
 * such as those while its check cooled down ({@see Cooldown}). With a
 * memory cache, a merged hit that changes nothing else, while the row was
 * written less than {@see DetectionHits::REFRESH} seconds ago, is only
 * counted there and writes no row.
 *
 * A new detection with an address keeps the address risk score at that
 * moment (fact `risk`), unless its check already stored the score it
 * lowered a limit with. Merged hits do not compute it again.
 */
class DetectionService {
	/** @var array<array-key, list<string>> the accounts recorded for detections in this request, by detection id */
	private array $recorded = [];

	public function __construct(
		private readonly DetectionMapper $mapper,
		private readonly CheckRegistry $registry,
		private readonly CheckSettings $settings,
		private readonly ITimeFactory $timeFactory,
		private readonly RiskScorer $risk,
		private readonly DetectionAccounts $accounts,
		private readonly DetectionTotals $totals,
		private readonly KeyLock $locks,
		private readonly Fingerprinter $fingerprinter,
		private readonly DetectionHits $hits,
	) {
	}

	/**
	 * @return array{0: Detection, 1: bool, 2: int} the stored detection, whether it is new, and how many hits it stands for (with those counted while its check cooled down)
	 */
	public function record(DetectionDraft $draft, ModeState $mode): array {
		$mergeKey = $draft->mergeKey($this->fingerprinter);
		if ($mergeKey === null) {
			return $this->recordUnlocked($draft, $mode);
		}
		// Parallel hits of one attack would otherwise each insert a detection, or lose a hit.
		return $this->locks->run('detection', $mergeKey, fn (): array => $this->recordUnlocked($draft, $mode));
	}

	/**
	 * @return array{0: Detection, 1: bool, 2: int}
	 */
	private function recordUnlocked(DetectionDraft $draft, ModeState $mode): array {
		$now = $this->timeFactory->getTime();
		$existing = $this->mergeTarget($draft, $mode);
		if ($existing !== null) {
			$accountsBefore = DetectionAccounts::of($existing);
			$severity = Severity::tryFrom($existing->getSeverity());
			$raised = $draft->severity !== null && ($severity === null || $draft->severity->rank() > $severity->rank());
			$explanation = $existing->getExplanationData();
			$facts = is_array($explanation['facts'] ?? null) ? $explanation['facts'] : [];
			$merged = FactsMerger::merge($facts, $draft);
			if (!$raised && $merged === $facts && $existing->getLastSeenAt() > $now - DetectionHits::REFRESH && $this->hits->count((string)$existing->getId())) {
				// Nothing new for the row; the hit waits in the cache. The entity tells the responses when it was seen.
				$existing->setLastSeenAt($now);
				$existing->resetUpdatedFields();
				$this->recorded[(string)$existing->getId()] = $this->accounts->recordChange($existing, $accountsBefore);
				return [$existing, false, 1];
			}
			// The hits counted in the memory cache meanwhile, e.g. while its check cooled down, join this one.
			[$pending] = $this->hits->take((string)$existing->getId());
			if ($raised) {
				// A stronger sign in the same attack raises the detection, e.g. a decoy's secret after its login name.
				$existing->setSeverity($draft->severity->value);
			}
			$explanation['last'] = $now;
			$explanation['facts'] = $merged;
			$existing->setExplanationData($explanation);
			$this->mapper->updateMerged($existing, 1 + $pending, $now);
			if ($raised) {
				$this->totals->raised($existing, $now);
			}
			// The merged facts may name accounts the detection did not name before.
			$this->recorded[(string)$existing->getId()] = $this->accounts->recordChange($existing, $accountsBefore);
			return [$existing, false, 1 + $pending];
		}

		$detection = $this->mapper->insert($this->build($draft, $mode, $now, true));
		$detection->resetUpdatedFields();
		$this->totals->created($detection);
		$this->recorded[(string)$detection->getId()] = $this->accounts->recordNew($detection);
		return [$detection, true, 1];
	}

	/**
	 * The stored detection a draft is merged into: the latest one with its
	 * merge key within the merge window, recorded in the same mode, and not
	 * answered with "Was this you?" yet. An answered detection stays as it
	 * was answered; a later hit starts a new one.
	 */
	public function mergeTarget(DetectionDraft $draft, ModeState $mode): ?Detection {
		$mergeKey = $draft->mergeKey($this->fingerprinter);
		if ($mergeKey === null) {
			return null;
		}
		$existing = $this->mapper->findMergeable($mergeKey, $this->timeFactory->getTime() - $draft->mergeWindow);
		if ($existing === null || $existing->isEnforced() !== $mode->acts() || $existing->getUserVerdict() !== null) {
			return null;
		}
		return $existing;
	}

	/**
	 * The detection a draft would become, without storing it, for simulations.
	 */
	public function preview(DetectionDraft $draft, ModeState $mode): Detection {
		return $this->build($draft, $mode, $this->timeFactory->getTime());
	}

	private function build(DetectionDraft $draft, ModeState $mode, int $now, bool $withRisk = false): Detection {
		$definition = $this->registry->get($draft->checkId);
		$detection = new Detection();
		$detection->setCheckId($draft->checkId);
		$detection->setSeverity(($draft->severity ?? $definition->severity)->value);
		$detection->setEnforced($mode->acts());
		$detection->setIp($draft->source?->ip);
		$detection->setNetKey($draft->source?->netKey);
		$detection->setUid($draft->uid);
		$detection->setShareId($draft->shareId);
		$detection->setMergeKey($draft->mergeKey($this->fingerprinter));
		$explanation = Explanation::build(
			$draft,
			$mode,
			$this->settings->params($draft->checkId),
			$now,
		);
		if ($withRisk && $draft->source !== null && !isset($draft->facts[RiskAssessment::FACTS_KEY]) && $this->risk->isEnabled()) {
			$facts = is_array($explanation['facts'] ?? null) ? $explanation['facts'] : [];
			$facts[RiskAssessment::FACTS_KEY] = $this->risk->score($draft->source)->toArray();
			$explanation['facts'] = $facts;
		}
		$detection->setExplanationData($explanation);
		$detection->setActionList([]);
		$detection->setCreatedTime($now);
		$detection->setLastSeenAt($now);
		$detection->setHits(1);
		return $detection;
	}

	/**
	 * Store the actions of a detection; nothing is written when they did
	 * not change since it was recorded.
	 *
	 * @param list<array{type: string, enforced: bool, ref?: mixed, note?: string}> $actions
	 */
	public function setActions(Detection $detection, array $actions): void {
		$detection->setActionList($actions);
		if (!isset($detection->getUpdatedFields()['actions'])) {
			return;
		}
		$this->mapper->update($detection);
		$detection->resetUpdatedFields();
		$this->recorded[(string)$detection->getId()] = $this->accounts->recordChange($detection, $this->recorded[(string)$detection->getId()] ?? null);
	}
}
