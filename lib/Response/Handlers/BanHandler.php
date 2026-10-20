<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Response\Handlers;

use OCA\IntrusionDetection\Check\Checks\SharedAddress;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Explain\IDescribesAction;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\BanResult;
use OCA\IntrusionDetection\Response\BanService;
use OCA\IntrusionDetection\Response\IResponseHandler;
use OCA\IntrusionDetection\Response\ResponseContext;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCA\IntrusionDetection\Response\ResponseOutcome;
use OCP\IL10N;
use Psr\Container\ContainerInterface;

/**
 * Blocks the detection's source (and, for some checks, further sources).
 * When the safety valve keeps an address from being blocked, a
 * `shared_address` detection tells the admin instead.
 */
class BanHandler implements IResponseHandler, IDescribesAction {
	/** At most this many blocks are listed in the action; the rest are counted */
	public const MAX_LISTED = 20;

	public function __construct(
		private readonly BanService $bans,
		private readonly ContainerInterface $container,
	) {
	}

	#[\Override]
	public function type(): ResponseType {
		return ResponseType::Ban;
	}

	#[\Override]
	public function apply(ResponseContext $context): ResponseOutcome {
		$draft = $context->draft;
		$listed = [];
		$counts = ['banned' => 0, 'already' => 0, 'skipped' => 0];
		foreach ($draft->banTargets() as $target) {
			$result = $this->bans->ban($target, $draft->checkId, $context->detection->getId(), $draft->banLevel);
			if ($result->outcome === BanResult::SKIPPED_SHARED && $draft->checkId !== SharedAddress::ID) {
				$this->reportShared($draft, $target, $result->sharedUsers);
			}
			if ($result->ban === null) {
				$counts['skipped']++;
				continue;
			}
			$counts[$result->outcome === BanResult::ALREADY ? 'already' : 'banned']++;
			foreach ([$result->ban, $result->netBan] as $ban) {
				if ($ban !== null && count($listed) < self::MAX_LISTED) {
					$listed[$ban->getId()] = [
						'id' => $ban->getId(),
						'reference' => $ban->getDisplayReference(),
						'cidr' => $ban->getCidr(),
						'level' => $ban->getLevel(),
						'until' => $ban->getExpiresAt(),
					];
				}
			}
		}
		$ref = ['bans' => array_values($listed), 'counts' => $counts];
		if ($counts['banned'] === 0 && $counts['already'] === 0) {
			return ResponseOutcome::skipped(ResponseOutcome::NOTE_NOTHING_TO_DO, $ref);
		}
		return ResponseOutcome::done($ref);
	}

	#[\Override]
	public function describeAction(array $action, IL10N $l, DateFormatter $dates): array {
		$ref = is_array($action['ref'] ?? null) ? $action['ref'] : [];
		$sentences = [];
		foreach ((array)($ref['bans'] ?? []) as $ban) {
			if (!is_array($ban)) {
				continue;
			}
			$sentences[] = $l->t('Blocked %1$s until %2$s (reference %3$s, %4$s).', [
				(string)($ban['cidr'] ?? ''),
				$dates->dateTime((int)($ban['until'] ?? 0)),
				(string)($ban['reference'] ?? ''),
				match ((int)($ban['level'] ?? 1)) {
					1 => $l->t('first block'),
					2 => $l->t('second block within the history window'),
					default => $l->t('repeat offender'),
				},
			]);
		}
		$counts = is_array($ref['counts'] ?? null) ? $ref['counts'] : [];
		$listed = count($sentences);
		$more = (int)($counts['banned'] ?? 0) + (int)($counts['already'] ?? 0) - $listed;
		if ($more > 0) {
			$sentences[] = $l->n('%n more address was blocked.', '%n more addresses were blocked.', $more);
		}
		if ((int)($counts['skipped'] ?? 0) > 0) {
			$sentences[] = $l->n(
				'%n address was not blocked: it is on the allowlist, is the server itself, or many people log in from it.',
				'%n addresses were not blocked: they are on the allowlist, are the server itself, or many people log in from them.',
				(int)$counts['skipped'],
			);
		}
		return $sentences;
	}

	private function reportShared(DetectionDraft $draft, SourceKey $target, int $users): void {
		// Resolved lazily: the engine runs this handler, so it cannot be a constructor dependency.
		$engine = $this->container->get(ResponseEngine::class);
		$engine->handle(new DetectionDraft(
			checkId: SharedAddress::ID,
			source: $target,
			facts: ['users' => $users, 'wantedBy' => $draft->checkId],
			merge: DetectionDraft::MERGE_SOURCE,
			mergeWindow: 86400,
		));
	}
}
