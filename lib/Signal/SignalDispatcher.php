<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Signal;

use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Response\ResponseEngine;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * Runs the detectors of a signal, in the order of {@see CheckRegistry::DETECTORS}:
 *
 * 1. the effective mode of the detector's check decides whether it runs; the
 *    modes are read from the static lexicon data, and a detector whose check
 *    does not run is neither loaded nor built;
 * 2. the detector judges the signal and returns drafts;
 * 3. the {@see ResponseEngine} records and answers each draft;
 * 4. a final draft answers the signal: no later detector runs.
 *
 * Each detector runs on its own: one that fails is logged, and the next one
 * still runs.
 */
class SignalDispatcher {
	public function __construct(
		private readonly CheckSettings $settings,
		private readonly ResponseEngine $engine,
		private readonly ContainerInterface $container,
		private readonly LoggerInterface $logger,
	) {
	}

	/**
	 * @param ?ModeState $mode run the detectors in this mode instead of their checks' own (a change of the settings is judged by the mode before it)
	 */
	public function dispatch(#[\SensitiveParameter] ISignal $signal, ?ModeState $mode = null): Dispatch {
		$detections = [];
		foreach (self::detectors($signal::class) as $checkId => $class) {
			$state = $mode ?? $this->settings->modeState($checkId);
			if (!$state->runs()) {
				continue;
			}
			try {
				$final = $this->run($class, $signal, $state, $detections);
			} catch (\Throwable $e) {
				$this->logger->error('Intrusion detection step {step} failed on {signal}', [
					'step' => $checkId,
					'signal' => substr(strrchr($signal::class, '\\') ?: $signal::class, 1),
					'exception' => $e,
				]);
				continue;
			}
			if ($final) {
				return new Dispatch($detections, true);
			}
		}
		return new Dispatch($detections, false);
	}

	/**
	 * Whether a detector of the signal runs: for the work a listener does
	 * only for them, such as recording an attempt.
	 *
	 * @param class-string<ISignal> $signal
	 * @param ?class-string $detector only this detector of the signal
	 */
	public function runs(string $signal, ?string $detector = null): bool {
		foreach (self::detectors($signal) as $checkId => $class) {
			if (($detector === null || $class === $detector) && $this->settings->modeState($checkId)->runs()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Whether a detector of the signal acts: for what a listener enforces
	 * itself, such as holding back an email.
	 *
	 * @param class-string<ISignal> $signal
	 */
	public function acts(string $signal): bool {
		foreach (self::detectors($signal) as $checkId => $class) {
			if ($this->settings->modeState($checkId)->acts()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * @param class-string<IDetector> $class
	 * @param list<Detection> $detections
	 * @return bool whether a draft was final
	 */
	private function run(string $class, #[\SensitiveParameter] ISignal $signal, ModeState $mode, array &$detections): bool {
		$detector = $this->container->get($class);
		if (!$detector instanceof IDetector) {
			throw new \LogicException($class . ' is no detector');
		}
		// Delegating passes each stored detection on to a detector that is a generator.
		$generator = (static fn (iterable $drafts): \Generator => yield from $drafts)($detector->detect($signal, $mode));
		$final = false;
		while ($generator->valid()) {
			$draft = $generator->current();
			if (!$draft instanceof DetectionDraft) {
				throw new \LogicException($class . ' returned no draft');
			}
			$detection = $this->engine->handle($draft);
			if ($detection !== null) {
				$detections[] = $detection;
			}
			$final = $final || $draft->final;
			$generator->send($detection);
		}
		return $final;
	}

	/**
	 * @param class-string<ISignal> $signal
	 * @return array<string, class-string<IDetector>> by check id
	 */
	private static function detectors(string $signal): array {
		return CheckRegistry::DETECTORS[$signal] ?? [];
	}
}
