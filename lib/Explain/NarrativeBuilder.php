<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Explain;

use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\CheckTexts;
use OCA\IntrusionDetection\Check\InvalidParamException;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCA\IntrusionDetection\Response\ResponseOutcome;
use OCA\IntrusionDetection\ResponseDefinitions;
use OCA\IntrusionDetection\Risk\RiskExplainer;
use OCP\IL10N;
use Psr\Container\ContainerInterface;

/**
 * Renders a stored detection into "what happened, and what Nextcloud did".
 * When the address risk score of the detection lowered a limit, or the
 * score was not 0, the check's own sentences are followed by one about it.
 *
 * @psalm-import-type IntrusionDetectionRisk from ResponseDefinitions
 */
class NarrativeBuilder {
	public function __construct(
		private readonly CheckRegistry $registry,
		private readonly ContainerInterface $container,
		private readonly DateFormatter $dates,
		private readonly RiskExplainer $risk,
	) {
	}

	public function build(Detection $detection, IL10N $l): Narrative {
		$explanation = $detection->getExplanationData();
		try {
			$definition = $this->registry->get($detection->getCheckId());
			$texts = $definition->texts($l);
			$title = $texts->name;
			$check = $this->container->get($this->registry->classOf($detection->getCheckId()));
		} catch (InvalidParamException) {
			// A detection of a check that no longer exists can still be shown.
			$title = $detection->getCheckId();
			$texts = null;
			$check = null;
		}

		$happened = $check instanceof IExplainsDetection
			? $check->narrative($detection, $l)
			: $this->genericHappened($detection, $l, $texts?->summary ?? '');
		array_push($happened, ...$this->risk->sentences($detection, $l, $texts));

		return new Narrative($title, $happened, $this->done($detection, $l), $this->observedBecause($detection, $explanation, $l));
	}

	/**
	 * The breakdown of the detection's risk score, for its detail.
	 *
	 * @return ?IntrusionDetectionRisk
	 */
	public function risk(Detection $detection, IL10N $l): ?array {
		return $this->risk->present($detection, $l, $this->texts($detection, $l));
	}

	private function texts(Detection $detection, IL10N $l): ?CheckTexts {
		try {
			return $this->registry->get($detection->getCheckId())->texts($l);
		} catch (InvalidParamException) {
			return null;
		}
	}

	/**
	 * @return list<string>
	 */
	private function genericHappened(Detection $detection, IL10N $l, string $summary): array {
		$sentences = $summary !== '' ? [$summary] : [];
		if ($detection->getIp() !== null) {
			$sentences[] = $l->t('The address was %s.', [$detection->getIp()]);
		}
		if ($detection->getUid() !== null) {
			$sentences[] = $l->t('It concerned the account %s.', [$detection->getUid()]);
		}
		if ($detection->getHits() > 1) {
			$sentences[] = $l->n(
				'It happened %n time between %1$s and %2$s.',
				'It happened %n times between %1$s and %2$s.',
				$detection->getHits(),
				[$this->dates->dateTime($detection->getCreatedAt()), $this->dates->dateTime($detection->getLastSeenAt())],
			);
		}
		return $sentences;
	}

	/**
	 * @return list<string>
	 */
	private function done(Detection $detection, IL10N $l): array {
		$handlers = $this->handlers();
		$sentences = [];
		foreach ($detection->getActionList() as $action) {
			$type = ResponseType::tryFrom($action['type']);
			if ($type === null) {
				continue;
			}
			$note = $action['note'] ?? null;
			if ($note === ResponseOutcome::NOTE_UNAVAILABLE) {
				$sentences[] = $l->t('%s (not available on this server)', [$type->describe($l)]);
				continue;
			}
			if ($note === ResponseOutcome::NOTE_FAILED) {
				$sentences[] = $l->t('%s (this failed; the server log has the details)', [$type->describe($l)]);
				continue;
			}
			if ($note === ResponseOutcome::NOTE_NOTHING_TO_DO) {
				$sentences[] = $l->t('%s Nothing needed to be done.', [$type->describe($l)]);
				continue;
			}
			$handler = $handlers[$type->value] ?? null;
			$described = ($action['enforced'] || $note === ResponseOutcome::NOTE_HELD_BACK) && $handler instanceof IDescribesAction ? $handler->describeAction($action, $l, $this->dates) : [];
			if ($described !== []) {
				array_push($sentences, ...$described);
			} elseif ($action['enforced']) {
				$sentences[] = $type->describe($l);
			} else {
				$sentences[] = $l->t('Would have: %s', [$type->describe($l)]);
			}
		}
		if ($sentences === []) {
			$sentences[] = $l->t('Nothing: this check only records what it finds.');
		}
		return $sentences;
	}

	/**
	 * @param array<string, mixed> $explanation
	 */
	private function observedBecause(Detection $detection, array $explanation, IL10N $l): ?string {
		if ($detection->isEnforced()) {
			return null;
		}
		$reason = $explanation['mode']['reason'] ?? null;
		return match ($reason) {
			ModeState::REASON_LEARNING => $l->t('Nothing was done, because learning mode was on: Nextcloud was watching, not acting.'),
			ModeState::REASON_AUTHENTICATED => $l->t('Nothing was done, because the request came from a logged-in user, and this check only observes those.'),
			default => $l->t('Nothing was done, because this check was set to Observe.'),
		};
	}

	/**
	 * @return array<string, object>
	 */
	private function handlers(): array {
		$handlers = [];
		foreach (ResponseEngine::HANDLERS as $class) {
			$handler = $this->container->get($class);
			$handlers[$handler->type()->value] = $handler;
		}
		return $handlers;
	}
}
