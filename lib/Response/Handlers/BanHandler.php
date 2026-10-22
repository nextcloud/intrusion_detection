<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Response\Handlers;

use OCA\IntrusionDetection\Check\Checks\SharedAddress;
use OCA\IntrusionDetection\Db\Ban;
use OCA\IntrusionDetection\Definition\ResponseType;
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
 * When the safety valve or an unconfigured reverse proxy keeps an address
 * from being blocked, a `shared_address` detection tells the admin instead.
 * Addresses of this server's own people are not blocked either
 * ({@see \OCA\IntrusionDetection\Response\BanExemptions}); the action says so.
 *
 * The address of the request is not blocked when the request is a possible
 * lure ({@see \OCA\IntrusionDetection\Net\FetchMetadata}): a browser that
 * fetched a URL for another site's page or an email. Anyone could have caused
 * it, so it is recorded, but blocking it would let any page lock its visitors
 * out. Only the checks a plain link can trigger honour lures
 * ({@see \OCA\IntrusionDetection\Definition\CheckDefinition::$honoursLure});
 * failed logins and wrong share passwords never come from a lure.
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
		return $this->bans->batch(fn (): ResponseOutcome => $this->banAll($context));
	}

	private function banAll(ResponseContext $context): ResponseOutcome {
		$draft = $context->draft;
		$listed = [];
		$counts = ['banned' => 0, 'already' => 0, 'skipped' => 0, 'lure' => 0, 'trusted' => 0, 'proxy' => 0];
		$lure = $draft->lure && $context->definition->honoursLure ? $draft->source : null;
		$targets = [];
		foreach ($draft->banTargets() as $target) {
			if ($lure !== null && $target->ipKey === $lure->ipKey) {
				$counts['lure']++;
				continue;
			}
			$targets[$target->ipKey] = $target;
		}
		$results = $targets === [] ? [] : $this->bans->banMany(array_values($targets), $draft->checkId, $context->detection->getId(), $draft->banLevel, $draft->uid);
		foreach ($results as $ipKey => $result) {
			$target = $targets[$ipKey] ?? null;
			if ($target !== null && ($result->outcome === BanResult::SKIPPED_SHARED || $result->outcome === BanResult::SKIPPED_PROXY)
				&& $this->bans->firstReport($target)) {
				$this->reportShared($draft, $target, $result->sharedUsers, $result->outcome === BanResult::SKIPPED_PROXY);
			}
			$this->count($result, $draft, $counts, $listed);
		}
		foreach ($draft->networkBanTargets() as $member) {
			$this->count($this->bans->banNetwork($member, $draft->checkId, $context->detection->getId(), $draft->uid), $draft, $counts, $listed);
		}
		$ref = ['bans' => array_values($listed), 'counts' => $counts];
		if ($counts['banned'] === 0 && $counts['already'] === 0) {
			return ResponseOutcome::skipped($counts['lure'] + $counts['trusted'] + $counts['proxy'] > 0 ? ResponseOutcome::NOTE_HELD_BACK : ResponseOutcome::NOTE_NOTHING_TO_DO, $ref);
		}
		return ResponseOutcome::done($ref);
	}

	/**
	 * @param array<string, int> $counts
	 * @param array<int, array{id: int, reference: string, cidr: string, level: int, forced: bool, until: int}> $listed
	 */
	private function count(BanResult $result, DetectionDraft $draft, array &$counts, array &$listed): void {
		if ($result->ban === null) {
			$counts[match ($result->outcome) {
				BanResult::SKIPPED_TRUSTED => 'trusted',
				BanResult::SKIPPED_PROXY => 'proxy',
				default => 'skipped',
			}]++;
			return;
		}
		$counts[$result->outcome === BanResult::ALREADY ? 'already' : 'banned']++;
		foreach ([$result->ban, $result->netBan] as $ban) {
			if ($ban !== null && count($listed) < self::MAX_LISTED) {
				$listed[$ban->getId()] = $this->listed($ban, $draft);
			}
		}
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
				match (true) {
					(bool)($ban['forced'] ?? false) => $l->t('this check blocks for this long right away'),
					(int)($ban['level'] ?? 1) <= 1 => $l->t('first block'),
					(int)$ban['level'] === 2 => $l->t('second block within the history window'),
					default => $l->t('blocked again within the history window'),
				},
			]);
		}
		$counts = is_array($ref['counts'] ?? null) ? $ref['counts'] : [];
		$listed = count($sentences);
		$more = (int)($counts['banned'] ?? 0) + (int)($counts['already'] ?? 0) - $listed;
		if ($more > 0) {
			$sentences[] = $l->n('%n more address was blocked.', '%n more addresses were blocked.', $more);
		}
		if ((int)($counts['lure'] ?? 0) > 0) {
			$sentences[] = $l->t('The address of the request was not blocked: a browser made it for another website or an email, for example to show an image. Anyone can cause such a request, so it is only recorded.');
		}
		if ((int)($counts['trusted'] ?? 0) > 0) {
			$sentences[] = $l->n(
				'%n address was not blocked: within the last 7 days an administrator logged in from it, or the account the detection is about confirmed a login from it.',
				'%n addresses were not blocked: within the last 7 days an administrator logged in from them, or the account the detection is about confirmed a login from them.',
				(int)$counts['trusted'],
			);
		}
		if ((int)($counts['proxy'] ?? 0) > 0) {
			$sentences[] = $l->n(
				'%n address was not blocked: it is a private address several people or an administrator log in from while no trusted proxies are configured, so it is probably your reverse proxy.',
				'%n addresses were not blocked: they are private addresses several people or an administrator log in from while no trusted proxies are configured, so they are probably your reverse proxy.',
				(int)$counts['proxy'],
			);
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

	/**
	 * @return array{id: int, reference: string, cidr: string, level: int, forced: bool, until: int}
	 */
	private function listed(Ban $ban, DetectionDraft $draft): array {
		return [
			'id' => $ban->getId(),
			'reference' => $ban->getDisplayReference(),
			'cidr' => $ban->getCidr(),
			'level' => $ban->getLevel(),
			'forced' => $draft->banLevel !== null,
			'until' => $ban->getExpiresAt(),
		];
	}

	private function reportShared(DetectionDraft $draft, SourceKey $target, int $users, bool $proxy): void {
		// Resolved lazily: the engine runs this handler, so it cannot be a constructor dependency.
		$this->container->get(ResponseEngine::class)->handle(SharedAddress::draft($target, $users, $draft->checkId, $proxy));
	}
}
