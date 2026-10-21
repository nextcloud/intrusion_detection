<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Detection;

use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCP\AppFramework\Utility\ITimeFactory;

/**
 * Stores detections. Repeated hits of the same check from the same source
 * (or for the same user) within the merge window update one row, which keeps
 * the noise of traps and scanners small.
 */
class DetectionService {
	public function __construct(
		private readonly DetectionMapper $mapper,
		private readonly CheckRegistry $registry,
		private readonly Settings $settings,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * @return array{0: Detection, 1: bool} the stored detection, and whether it is new
	 */
	public function record(DetectionDraft $draft, ModeState $mode): array {
		$now = $this->timeFactory->getTime();
		$mergeKey = $draft->mergeKey();

		if ($mergeKey !== null) {
			$existing = $this->mapper->findMergeable($mergeKey, $now - $draft->mergeWindow);
			if ($existing !== null && $existing->isEnforced() === $mode->acts()) {
				$existing->setHits($existing->getHits() + 1);
				$existing->setLastSeenAt($now);
				$explanation = $existing->getExplanationData();
				$explanation['last'] = $now;
				$explanation['facts'] = array_replace($explanation['facts'] ?? [], $draft->facts);
				$existing->setExplanationData($explanation);
				$this->mapper->update($existing);
				return [$existing, false];
			}
		}

		return [$this->mapper->insert($this->build($draft, $mode, $now)), true];
	}

	/**
	 * The detection a draft would become, without storing it, for simulations.
	 */
	public function preview(DetectionDraft $draft, ModeState $mode): Detection {
		return $this->build($draft, $mode, $this->timeFactory->getTime());
	}

	private function build(DetectionDraft $draft, ModeState $mode, int $now): Detection {
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
		$detection->setExplanationData(Explanation::build(
			$draft,
			$mode,
			$this->settings->params($draft->checkId),
			$now,
		));
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
