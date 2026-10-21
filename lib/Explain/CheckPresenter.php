<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Explain;

use OCA\IntrusionDetection\Check\CheckDefinition;
use OCA\IntrusionDetection\Check\DataKind;
use OCA\IntrusionDetection\Check\ParamDefinition;
use OCA\IntrusionDetection\Check\Requirement;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Config\Prerequisites;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCP\IL10N;

/**
 * One check as the admin page and occ present it: its texts with the
 * current values filled in, its settings and its state.
 *
 * @psalm-import-type IntrusionDetectionPresentedCheck from ResponseDefinitions
 */
class CheckPresenter {
	public function __construct(
		private readonly Settings $settings,
		private readonly Prerequisites $prerequisites,
		private readonly TextRenderer $renderer,
	) {
	}

	/**
	 * @return IntrusionDetectionPresentedCheck
	 */
	public function present(CheckDefinition $check, IL10N $l): array {
		$texts = $check->texts($l);
		$values = $this->settings->placeholderValues($check->id);
		$state = $this->settings->modeState($check->id);
		$responses = $this->settings->responses($check->id);

		return [
			'id' => $check->id,
			'category' => $check->category->value,
			'internal' => $check->internal,
			'severity' => $check->severity->value,
			'mode' => [
				'configured' => $state->configured->value,
				'effective' => $state->effective->value,
				'reason' => $state->reason,
				'missing' => $state->missing?->value,
				'default' => $check->defaultMode->value,
			],
			'texts' => $texts->toArray(),
			// The template, for the page to fill in while the admin types.
			'decidesTemplate' => $texts->decides,
			'decides' => $this->renderer->fill($texts->decides, $values, $l, $check),
			'happens' => $this->happens($responses, $l, $values),
			'responses' => array_map(static fn (ResponseType $r): array => [
				'type' => $r->value,
				'label' => $r->describe($l),
				// A template like `decides`, filled in by the page as settings change.
				'happens' => $r->happens($l),
				'order' => $r->order(),
				'selected' => in_array($r, $responses, true),
				'default' => in_array($r, $check->defaultResponses, true),
			], $check->responses),
			'params' => array_map(fn (ParamDefinition $param): array => array_merge($param->toArray(), [
				'value' => $this->settings->param($check->id, $param->name),
				'label' => $texts->param($param->name)->label,
				'help' => $texts->param($param->name)->help,
				'unit' => $texts->param($param->name)->unit,
			]), $check->params),
			'cost' => [
				'class' => $check->cost->value,
				'text' => $check->cost->describe($l),
			],
			'requirements' => array_map(fn (Requirement $r): array => [
				'id' => $r->value,
				'met' => $this->prerequisites->isMet($r),
				'text' => $r->describe($l),
			], $check->requirements),
			'stores' => array_map(static fn (DataKind $k): string => $k->value, $check->stores),
			'sendsData' => $check->sendsData,
			'actsWhileLearning' => $check->actsWhileLearning,
			'simulatable' => $check->simulatable,
		];
	}

	/**
	 * "What happens": the selected responses as sentences, in the order they run.
	 *
	 * @param list<ResponseType> $responses
	 * @param array<string, int|float|bool|string|list<string>> $values placeholder values, see {@see Settings::placeholderValues()}
	 * @return list<string>
	 */
	public function happens(array $responses, IL10N $l, array $values = []): array {
		usort($responses, static fn (ResponseType $a, ResponseType $b): int => $a->order() <=> $b->order());
		return $responses === []
			? [$l->t('Nothing is done; detections are only recorded.')]
			: array_map(fn (ResponseType $r): string => $values === [] ? $r->describe($l) : $this->renderer->fill($r->happens($l), $values, $l), $responses);
	}
}
