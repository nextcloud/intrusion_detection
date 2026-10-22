<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Detection;

use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\ISelectsResponses;
use OCA\IntrusionDetection\Check\ISimulatable;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Definition\InvalidParamException;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Explain\CheckPresenter;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IL10N;

/**
 * "Simulate": what a check would report and do for an attack that just
 * reaches its current thresholds. Nothing is recorded, blocked or notified,
 * and the attacker is an address of the documentation range 198.51.100.0/24.
 * Used by occ intrusion:simulate and the admin page.
 *
 * @psalm-import-type IntrusionDetectionSimulation from ResponseDefinitions
 */
class Simulator {
	public const TEST_ADDRESS = '198.51.100.23';

	public function __construct(
		private readonly CheckRegistry $registry,
		private readonly Settings $settings,
		private readonly DetectionService $detections,
		private readonly NarrativeBuilder $narratives,
		private readonly CheckPresenter $presenter,
		private readonly ITimeFactory $timeFactory,
	) {
	}

	/**
	 * Whether the check exists, is configurable and can be simulated.
	 */
	public function canSimulate(string $id): bool {
		if (!$this->registry->has($id)) {
			return false;
		}
		$definition = $this->registry->get($id);
		return !$definition->internal
			&& $definition->simulatable
			&& $this->registry->check($this->registry->classOf($id)) instanceof ISimulatable;
	}

	/**
	 * @return IntrusionDetectionSimulation
	 * @throws InvalidParamException when the check does not exist or cannot be simulated
	 */
	public function simulate(string $id, IL10N $l): array {
		if (!$this->canSimulate($id)) {
			throw new InvalidParamException('unknown_check', ['check' => $id]);
		}
		$check = $this->registry->check($this->registry->classOf($id));
		if (!$check instanceof ISimulatable) {
			throw new InvalidParamException('unknown_check', ['check' => $id]);
		}

		$mode = $this->settings->modeState($id);
		$draft = $check->simulate(SourceKey::fromIp(self::TEST_ADDRESS), $this->timeFactory->getTime(), $this->settings->params($id));
		$detection = $this->detections->preview($draft, $mode);
		$responses = $this->settings->responses($id);
		if ($check instanceof ISelectsResponses) {
			$responses = $check->responsesFor($draft, $responses, $this->settings->params($id));
		}
		usort($responses, static fn (ResponseType $a, ResponseType $b): int => $a->order() <=> $b->order());
		$detection->setActionList(array_map(static fn (ResponseType $r): array => ['type' => $r->value, 'enforced' => false], $responses));
		$narrative = $this->narratives->build($detection, $l);
		$happens = $responses === [] ? [] : $this->presenter->happens($responses, $l, $this->settings->placeholderValues($id));

		return [
			'check' => $id,
			'testAddress' => self::TEST_ADDRESS,
			'mode' => $mode->effective->value,
			'modeReason' => $mode->reason,
			'runs' => $mode->runs(),
			'acts' => $mode->acts(),
			'severity' => $detection->getSeverity(),
			'narrative' => [
				'title' => $narrative->title,
				'happened' => $narrative->happened,
				'done' => $narrative->done,
				'observedBecause' => $narrative->observedBecause,
			],
			'responses' => array_map(static fn (ResponseType $r, string $text): array => [
				'type' => $r->value,
				'text' => $text,
			], $responses, $happens),
		];
	}
}
