<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Detection;

use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\Severity;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Risk\RiskAssessment;
use OCA\IntrusionDetection\Risk\RiskScorer;
use OCP\AppFramework\Utility\ITimeFactory;

/**
 * Stores detections. Repeated hits of the same check and rule from the same
 * source (or for the same user) within the merge window update one row,
 * which keeps the noise of traps and scanners small. The row's facts are
 * merged ({@see FactsMerger}), so it still explains every hit.
 *
 * A new detection with an address keeps the address risk score at that
 * moment (fact `risk`), unless its check already stored the score it
 * lowered a limit with. Merged hits do not compute it again.
 */
class DetectionService {
	public function __construct(
		private readonly DetectionMapper $mapper,
		private readonly CheckRegistry $registry,
		private readonly Settings $settings,
		private readonly ITimeFactory $timeFactory,
		private readonly RiskScorer $risk,
	) {
	}

	/**
	 * @return array{0: Detection, 1: bool} the stored detection, and whether it is new
	 */
	public function record(DetectionDraft $draft, ModeState $mode): array {
		$now = $this->timeFactory->getTime();
		$existing = $this->mergeTarget($draft, $mode);
		if ($existing !== null) {
			$existing->setHits($existing->getHits() + 1);
			$existing->setLastSeenAt($now);
			$severity = Severity::tryFrom($existing->getSeverity());
			if ($draft->severity !== null && ($severity === null || $draft->severity->rank() > $severity->rank())) {
				// A stronger sign in the same attack raises the detection, e.g. a decoy's secret after its login name.
				$existing->setSeverity($draft->severity->value);
			}
			$explanation = $existing->getExplanationData();
			$explanation['last'] = $now;
			$explanation['facts'] = FactsMerger::merge(is_array($explanation['facts'] ?? null) ? $explanation['facts'] : [], Explanation::facts($draft));
			$existing->setExplanationData($explanation);
			$this->mapper->update($existing);
			return [$existing, false];
		}

		return [$this->mapper->insert($this->build($draft, $mode, $now, true)), true];
	}

	/**
	 * The stored detection a draft is merged into: the latest one with its
	 * merge key within the merge window, recorded in the same mode, and not
	 * answered with "Was this you?" yet. An answered detection stays as it
	 * was answered; a later hit starts a new one.
	 */
	public function mergeTarget(DetectionDraft $draft, ModeState $mode): ?Detection {
		$mergeKey = $draft->mergeKey();
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
		$detection->setMergeKey($draft->mergeKey());
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
		$detection->setCreatedAt($now);
		$detection->setLastSeenAt($now);
		$detection->setHits(1);
		return $detection;
	}

	/**
	 * @param list<array{type: string, enforced: bool, ref?: mixed, note?: string}> $actions
	 */
	public function setActions(Detection $detection, array $actions): void {
		$detection->setActionList($actions);
		$this->mapper->update($detection);
	}
}
