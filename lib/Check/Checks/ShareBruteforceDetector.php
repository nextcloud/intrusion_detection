<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks;

use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Db\AttemptMapper;
use OCA\IntrusionDetection\Db\AttemptStats;
use OCA\IntrusionDetection\Detection\AttemptRecord;
use OCA\IntrusionDetection\Detection\AttemptRecorder;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCA\IntrusionDetection\Share\ShareLinks;
use OCP\Share\IShare;

/**
 * Detects share link attacks (concept section 10.9) after each failed share
 * access.
 *
 * 1. Token guessing: one address tried at least `token_min` different
 *    unknown tokens within `token_window`; an IPv4 /24 at least `net_factor`
 *    times that many from more than one address.
 * 2. Password guessing from one address: at least `password_min_per_source`
 *    wrong passwords for one share within `password_source_window`.
 * 3. Password guessing on one share: at least `password_min_per_share`
 *    wrong passwords for it from any addresses within `password_share_window`.
 *
 * Under a flood the recorder keeps one unknown token in FLOOD_SAMPLE; only a
 * kept one is evaluated, and the counts are scaled by the sample factor.
 * However the numbers are scaled, an address with at most STALE_TOLERANCE
 * distinct tokens never fires and is never blocked: outdated links are normal.
 */
class ShareBruteforceDetector {
	/** This many distinct unknown tokens per address never count */
	public const STALE_TOLERANCE = 2;
	/** A network detection blocks at most this many of its addresses */
	public const MAX_NET_TARGETS = 256;
	/** Repeated wrong passwords for one share within this time are one detection, and one message to its owner */
	public const SHARE_MERGE_WINDOW = 86400;

	public function __construct(
		private readonly Settings $settings,
		private readonly AttemptMapper $attempts,
		private readonly AttemptRecorder $recorder,
		private readonly ResponseEngine $engine,
		private readonly ShareBruteforce $check,
		private readonly ShareLinks $links,
	) {
	}

	public function unknownToken(#[\SensitiveParameter] AttemptRecord $attempt, ?string $userAgent): void {
		if ($attempt->kind !== AttemptKind::UnknownShareToken || !$attempt->stored) {
			return;
		}
		if (!$this->settings->modeState(ShareBruteforce::ID)->runs()) {
			return;
		}
		$params = $this->settings->params(ShareBruteforce::ID);
		$factor = $this->recorder->sampleFactor(AttemptKind::UnknownShareToken, $attempt->time);
		$minTokens = (int)$params['token_min'];
		$netFactor = (int)$params['net_factor'];
		$since = $attempt->time - (int)$params['token_window'];
		$source = $attempt->source;
		$kinds = [AttemptKind::UnknownShareToken];

		$ip = $this->attempts->stats('ip_key', [$source->ipKey], $kinds, $since);
		if (self::reaches($ip->distinctNames, $factor, $minTokens)) {
			$this->handle(new DetectionDraft(
				checkId: ShareBruteforce::ID,
				source: $source,
				facts: $this->tokenFacts(ShareBruteforce::RULE_TOKENS, $ip, $factor),
				merge: DetectionDraft::MERGE_SOURCE,
				userAgent: $userAgent,
			), $params);
			return;
		}
		if ($source->family !== 4 || $netFactor < 1) {
			return;
		}
		$net = $this->attempts->stats('net_key', [$source->netKey], $kinds, $since);
		if ($net->distinctSources < 2 || !self::reaches($net->distinctNames, $factor, $minTokens * $netFactor)) {
			return;
		}
		$draft = new DetectionDraft(
			checkId: ShareBruteforce::ID,
			source: $source,
			facts: $this->tokenFacts(ShareBruteforce::RULE_TOKENS_NETWORK, $net, $factor) + ['net' => $source->netKey],
			merge: DetectionDraft::MERGE_SOURCE,
			userAgent: $userAgent,
		);
		foreach ($this->attempts->distinctNamesPerSource('net_key', $source->netKey, $kinds, $since, self::MAX_NET_TARGETS) as $ipKey => $tokens) {
			$target = $tokens > self::STALE_TOLERANCE ? SourceKey::tryFromIpKey($ipKey) : null;
			if ($target !== null) {
				$draft->addBanTarget($target);
			}
		}
		$this->handle($draft, $params);
	}

	public function wrongPassword(#[\SensitiveParameter] AttemptRecord $attempt, IShare $share, ?string $userAgent): void {
		$shareId = $attempt->shareId;
		if ($attempt->kind !== AttemptKind::WrongSharePassword || $shareId === null) {
			return;
		}
		if (!$this->settings->modeState(ShareBruteforce::ID)->runs()) {
			return;
		}
		$params = $this->settings->params(ShareBruteforce::ID);
		$kinds = [AttemptKind::WrongSharePassword];
		$source = $attempt->source;
		$shareFacts = $this->shareFacts($share);

		$fromSource = $this->attempts->statsForSourceOnShare($source->ipKey, $shareId, $kinds, $attempt->time - (int)$params['password_source_window']);
		if ($fromSource->failures >= (int)$params['password_min_per_source']) {
			$this->handle(new DetectionDraft(
				checkId: ShareBruteforce::ID,
				source: $source,
				uid: $shareFacts['owner'],
				facts: [
					'rule' => ShareBruteforce::RULE_PASSWORD_SOURCE,
					'failures' => $fromSource->failures,
					'first' => $fromSource->first,
					'last' => $fromSource->last,
				] + $shareFacts,
				shareId: $shareId,
				// Not merged with token guessing from the same address, which is about no share.
				merge: DetectionDraft::MERGE_SOURCE_USER,
				userAgent: $userAgent,
			), $params);
		}

		$onShare = $this->attempts->stats('share_id', [$shareId], $kinds, $attempt->time - (int)$params['password_share_window']);
		if ($onShare->failures >= (int)$params['password_min_per_share']) {
			$this->handle(new DetectionDraft(
				checkId: ShareBruteforce::ID,
				uid: $shareFacts['owner'],
				facts: [
					'rule' => ShareBruteforce::RULE_PASSWORD_SHARE,
					'failures' => $onShare->failures,
					'sources' => $onShare->distinctSources,
					'first' => $onShare->first,
					'last' => $onShare->last,
					'lastSource' => $source->ip,
				] + $shareFacts,
				shareId: $shareId,
				merge: DetectionDraft::MERGE_SHARE,
				mergeWindow: self::SHARE_MERGE_WINDOW,
				userAgent: $userAgent,
			), $params);
		}
	}

	/**
	 * @param array<string, int|float|bool|string|list<string>> $params
	 */
	private function handle(DetectionDraft $draft, array $params): void {
		$this->engine->handle($draft, $this->check->responsesFor($draft, $this->settings->responses(ShareBruteforce::ID), $params));
	}

	/**
	 * Whether a raw count of distinct tokens, scaled by the sample factor,
	 * reaches a threshold, and is more than a few outdated links.
	 */
	public static function reaches(int $raw, int $factor, int $threshold): bool {
		return $raw > self::STALE_TOLERANCE && $raw * $factor >= $threshold;
	}

	/**
	 * @return array<string, mixed>
	 */
	private function tokenFacts(string $rule, AttemptStats $stats, int $factor): array {
		return [
			'rule' => $rule,
			'tokens' => $stats->distinctNames * $factor,
			'attempts' => $stats->failures * $factor,
			'sources' => $stats->distinctSources,
			'sampleFactor' => $factor,
			'first' => $stats->first,
			'last' => $stats->last,
		];
	}

	/**
	 * Identifiers only: the share's full id and type, and the accounts that
	 * manage it. Never its token or its name.
	 *
	 * @return array{owner: ?string, managers: list<string>, share: string, shareType: int, targets: list<string>}
	 */
	private function shareFacts(IShare $share): array {
		$managers = $this->links->managers($share);
		return [
			'owner' => $managers[0] ?? null,
			'managers' => $managers,
			'share' => $share->getFullId(),
			'shareType' => $share->getShareType(),
			'targets' => $managers,
		];
	}
}
