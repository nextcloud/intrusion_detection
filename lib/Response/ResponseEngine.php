<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Response;

use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Detection\DetectionService;
use OCA\IntrusionDetection\Event\TypedEvents;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * Turns a detection into actions.
 *
 * 1. Read the check's effective mode (learning mode and prerequisites applied).
 *    Off: nothing is recorded.
 * 2. Store the detection (merging repeats).
 * 3. Run the configured responses in their fixed order: blocks first,
 *    notifications last, so a notification can say what was done.
 *    In Observe every action is recorded as "would have" and nothing happens.
 *
 * Each response is idempotent. A response that fails is logged and recorded
 * as failed; the others still run.
 */
class ResponseEngine {
	/** @var list<class-string<IResponseHandler>> */
	public const HANDLERS = [
		Handlers\BanHandler::class,
		Handlers\FlagSourceHandler::class,
		Handlers\FlagPasswordHandler::class,
		Handlers\ProtectAccountHandler::class,
		Handlers\NotifyAdminHandler::class,
		Handlers\NotifyShareOwnerHandler::class,
		Handlers\SuppressResetMailHandler::class,
		Handlers\KillSessionHandler::class,
		Handlers\RevokeTokenHandler::class,
		Handlers\ForcePasswordChangeHandler::class,
		Handlers\NotifyUserHandler::class,
		Handlers\StepUpHandler::class,
		Handlers\RateLimitHandler::class,
	];

	/** @var array<string, IResponseHandler>|null */
	private ?array $handlers = null;

	public function __construct(
		private readonly CheckRegistry $registry,
		private readonly Settings $settings,
		private readonly DetectionService $detections,
		private readonly ContainerInterface $container,
		private readonly TypedEvents $events,
		private readonly AuditLogger $audit,
		private readonly LoggerInterface $logger,
	) {
	}

	/**
	 * @param list<ResponseType>|null $responses run these instead of the configured ones
	 * @param ?ModeState $mode use this mode instead of the check's, for checks with more than one (e.g. one for logged-in users)
	 * @return ?Detection the stored detection, or null when the check is off
	 */
	public function handle(DetectionDraft $draft, ?array $responses = null, ?ModeState $mode = null): ?Detection {
		$definition = $this->registry->get($draft->checkId);
		$mode ??= $this->settings->modeState($draft->checkId);
		if (!$mode->runs()) {
			return null;
		}

		[$detection, $isNew] = $this->detections->record($draft, $mode);

		$responses ??= $this->settings->responses($draft->checkId);
		usort($responses, static fn (ResponseType $a, ResponseType $b): int => $a->order() <=> $b->order());

		$context = new ResponseContext($draft, $detection, $definition, $isNew);
		$actions = $isNew ? [] : $detection->getActionList();
		foreach ($responses as $response) {
			$actions = $this->replaceAction($actions, $this->run($response, $context, $mode->acts()));
			// Later responses (the notifications) can say what the earlier ones did.
			$detection->setActionList($actions);
		}
		$this->detections->setActions($detection, $actions);

		if ($isNew) {
			$this->audit->log('%s detected (%s, %s), source %s, account %s', [
				'check' => $draft->checkId,
				'severity' => $detection->getSeverity(),
				'mode' => $mode->acts() ? 'enforced' : 'observed',
				'ip' => $draft->source?->ip,
				'uid' => $draft->uid,
			]);
			$this->events->detectionCreated($detection);
		}
		return $detection;
	}

	/**
	 * @return array{type: string, enforced: bool, ref?: mixed, note?: string}
	 */
	private function run(ResponseType $response, ResponseContext $context, bool $acts): array {
		$handler = $this->handler($response);
		if ($handler === null) {
			return ['type' => $response->value, 'enforced' => false, 'note' => ResponseOutcome::NOTE_UNAVAILABLE];
		}
		if (!$acts) {
			return ['type' => $response->value, 'enforced' => false];
		}
		try {
			$outcome = $handler->apply($context);
		} catch (\Throwable $e) {
			$this->logger->error('Intrusion detection response {response} failed for {check}', [
				'response' => $response->value,
				'check' => $context->definition->id,
				'exception' => $e,
			]);
			return ['type' => $response->value, 'enforced' => false, 'note' => ResponseOutcome::NOTE_FAILED];
		}
		$action = ['type' => $response->value, 'enforced' => $outcome->enforced];
		if ($outcome->ref !== null) {
			$action['ref'] = $outcome->ref;
		}
		if ($outcome->note !== null) {
			$action['note'] = $outcome->note;
		}
		return $action;
	}

	/**
	 * @param list<array{type: string, enforced: bool, ref?: mixed, note?: string}> $actions
	 * @param array{type: string, enforced: bool, ref?: mixed, note?: string} $action
	 * @return list<array{type: string, enforced: bool, ref?: mixed, note?: string}>
	 */
	private function replaceAction(array $actions, array $action): array {
		foreach ($actions as $i => $existing) {
			if ($existing['type'] === $action['type']) {
				// A merged hit keeps what was done before unless something new was done now.
				if ($action['enforced'] || !$existing['enforced']) {
					$actions[$i] = $action;
				}
				return $actions;
			}
		}
		$actions[] = $action;
		return $actions;
	}

	private function handler(ResponseType $response): ?IResponseHandler {
		if ($this->handlers === null) {
			$this->handlers = [];
			foreach (self::HANDLERS as $class) {
				$handler = $this->container->get($class);
				if ($handler instanceof IResponseHandler) {
					$this->handlers[$handler->type()->value] = $handler;
				}
			}
		}
		return $this->handlers[$response->value] ?? null;
	}
}
