<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks\ShareBruteforce;

use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Db\AttemptMapper;
use OCA\IntrusionDetection\Db\AttemptStats;
use OCA\IntrusionDetection\Detection\AttemptRecord;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCA\IntrusionDetection\Risk\RiskScorer;
use OCA\IntrusionDetection\Share\FederationPartners;
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
 * Each limit is lowered when the address of the failed access has an
 * elevated or high risk score ({@see RiskScorer::limits()}).
 *
 * A possible lure (a browser that opened the link for another site or an
 * email) counts, but the ban response spares the address of that request,
 * and attempts that may have been lures never make an address of the
 * network a target.
 *
 * Unknown tokens from the address of a server this one shares files with
 * ({@see FederationPartners}) count and are reported, but never block that
 * address: partner servers still open federated shares that were deleted
 * here without telling them.
 *
 * Under a flood the recorder keeps one unknown token in FLOOD_SAMPLE; only a
 * kept one is evaluated, and each kept row counts with its stored weight.
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
		private readonly CheckSettings $settings,
		private readonly AttemptMapper $attempts,
		private readonly ResponseEngine $engine,
		private readonly ShareLinks $links,
		private readonly RiskScorer $risk,
		private readonly FederationPartners $partners,
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
		$minTokens = (int)$params['token_min'];
		$netFactor = (int)$params['net_factor'];
		$since = $attempt->time - (int)$params['token_window'];
		$source = $attempt->source;
		$kinds = [AttemptKind::UnknownShareToken];

		// A logged-in user is told about, never blocked ({@see ShareBruteforce::responsesFor()}).
		$loggedIn = $attempt->uid !== null ? ['loggedIn' => true] : [];

		$ip = $this->attempts->stats('ip_key', [$source->ipKey], $kinds, $since);
		$limits = $this->risk->limits($source, ['token_min' => [$minTokens, $ip->namesEstimate()]]);
		if (self::reaches($ip->distinctNames, $ip->namesEstimate(), $limits->of('token_min'))) {
			// A partner server is reported, never blocked ({@see ShareBruteforce::responsesFor()}).
			$partner = $this->partners->isPartner($source) ? ['federation' => true] : [];
			$this->engine->handle(new DetectionDraft(
				checkId: ShareBruteforce::ID,
				source: $source,
				uid: $attempt->uid,
				facts: $this->tokenFacts(ShareBruteforce::RULE_TOKENS, $ip) + $loggedIn + $partner + $limits->facts(),
				merge: DetectionDraft::MERGE_SOURCE,
				userAgent: $userAgent,
				lure: $attempt->lure,
			));
			return;
		}
		if ($source->family !== 4 || $netFactor < 1) {
			return;
		}
		$net = $this->attempts->stats('net_key', [$source->netKey], $kinds, $since);
		if ($net->distinctSources < 2) {
			return;
		}
		$netLimits = $this->risk->limits($source, ['token_min' => [$minTokens * $netFactor, $net->namesEstimate()]]);
		if (!self::reaches($net->distinctNames, $net->namesEstimate(), $netLimits->of('token_min'))) {
			return;
		}
		$targets = [];
		foreach ($this->attempts->distinctNamesPerSource('net_key', $source->netKey, $kinds, $since, self::MAX_NET_TARGETS) as $ipKey => $tokens) {
			$target = $tokens > self::STALE_TOLERANCE ? SourceKey::tryFromIpKey($ipKey) : null;
			if ($target !== null) {
				$targets[$target->ipKey] = $target;
			}
		}
		$partners = $this->partners->among(array_values($targets));
		foreach ($partners as $partner) {
			unset($targets[$partner]);
		}
		$draft = new DetectionDraft(
			checkId: ShareBruteforce::ID,
			source: $source,
			uid: $attempt->uid,
			facts: $this->tokenFacts(ShareBruteforce::RULE_TOKENS_NETWORK, $net) + ['net' => $source->netKey] + $loggedIn
				+ ($partners === [] ? [] : ['partners' => count($partners)]) + $netLimits->facts(),
			merge: DetectionDraft::MERGE_SOURCE,
			userAgent: $userAgent,
			lure: $attempt->lure,
		);
		foreach ($targets as $target) {
			$draft->addBanTarget($target);
		}
		if (!isset($targets[$source->ipKey])) {
			// One or two outdated links never get an address blocked, not even the one that tipped the network over; nor does a partner server.
			$draft->spareSource();
		}
		$this->engine->handle($draft);
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
		$sourceLimits = $this->risk->limits($source, ['password_min_per_source' => [(int)$params['password_min_per_source'], $fromSource->failures]]);
		if ($sourceLimits->reached()) {
			// About the address, not the account: the owner is told only of attacks from many addresses.
			$this->engine->handle(new DetectionDraft(
				checkId: ShareBruteforce::ID,
				source: $source,
				facts: [
					'rule' => ShareBruteforce::RULE_PASSWORD_SOURCE,
					'failures' => $fromSource->failures,
					'first' => $fromSource->first,
					'last' => $fromSource->last,
				] + $shareFacts + $sourceLimits->facts(),
				shareId: $shareId,
				merge: DetectionDraft::MERGE_SOURCE_SHARE,
				userAgent: $userAgent,
			));
		}

		$onShare = $this->attempts->stats('share_id', [$shareId], $kinds, $attempt->time - (int)$params['password_share_window']);
		$shareLimits = $this->risk->limits($source, ['password_min_per_share' => [(int)$params['password_min_per_share'], $onShare->failures]]);
		if ($shareLimits->reached()) {
			$this->engine->handle(new DetectionDraft(
				checkId: ShareBruteforce::ID,
				uid: $shareFacts['owner'],
				facts: [
					'rule' => ShareBruteforce::RULE_PASSWORD_SHARE,
					'failures' => $onShare->failures,
					'sources' => $onShare->distinctSources,
					'first' => $onShare->first,
					'last' => $onShare->last,
					'lastSource' => $source->ip,
				] + $shareFacts + $shareLimits->facts(),
				shareId: $shareId,
				merge: DetectionDraft::MERGE_SHARE,
				mergeWindow: self::SHARE_MERGE_WINDOW,
				userAgent: $userAgent,
			));
		}
	}

	/**
	 * Whether a count of distinct tokens reaches a threshold: its estimate
	 * (stored rows scaled by their weight) reaches it, and the stored rows
	 * are more than a few outdated links.
	 */
	public static function reaches(int $raw, int $estimate, int $threshold): bool {
		return $raw > self::STALE_TOLERANCE && $estimate >= $threshold;
	}

	/**
	 * @return array<string, mixed>
	 */
	private function tokenFacts(string $rule, AttemptStats $stats): array {
		return [
			'rule' => $rule,
			'tokens' => $stats->namesEstimate(),
			'attempts' => $stats->failuresEstimate(),
			'sources' => $stats->distinctSources,
			'sampleFactor' => $stats->maxWeight,
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
