<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Check\Checks;

use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Guard\RequestContext;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCA\IntrusionDetection\SessionState\CurrentSession;
use OCA\IntrusionDetection\SessionState\SessionBlock;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IRequest;
use Psr\Container\ContainerInterface;

/**
 * Counts the directory requests of logged-in accounts (concept section
 * 10.16) in the memory cache, per account, kind of request and fixed
 * 10-minute bucket.
 *
 * - Below the limit, a request costs one cache increment (the first one of
 *   a bucket also sets the counter's lifetime) and two app config reads that
 *   are already loaded: no database, no check definitions.
 * - The request that goes above the limit records the detection once per
 *   bucket, with the configured responses.
 * - While the check acts with the rate-limit response, every request above
 *   the limit is refused with 429 until the bucket ends.
 *
 * Without a memory cache nothing is counted: the check is unavailable then.
 */
class DirectoryScrapingDetector {
	/** The namespace of its memory cache in {@see Caches} */
	public const CACHE = 'directory-scraping';
	public const KEY_PREFIX = 'scrape:';

	public function __construct(
		private readonly Settings $settings,
		private readonly RequestContext $context,
		private readonly Caches $caches,
		private readonly ITimeFactory $timeFactory,
		private readonly ContainerInterface $container,
	) {
	}

	/**
	 * Count one directory request of an account.
	 *
	 * @param string $group one of {@see \OCA\IntrusionDetection\Sensitive\DirectoryRoutes::GROUPS}
	 * @return ?SessionBlock the 429 answer while the account is above the limit
	 */
	public function count(string $uid, string $group): ?SessionBlock {
		$limitDefinition = DirectoryScraping::LIMITS[$group] ?? null;
		if ($limitDefinition === null || !$this->runs()) {
			return null;
		}
		$cache = $this->caches->shared(self::CACHE);
		if ($cache === null) {
			return null;
		}
		$now = $this->timeFactory->getTime();
		$bucket = intdiv($now, DirectoryScraping::WINDOW);
		$key = self::KEY_PREFIX . $group . ':' . $bucket . ':' . hash('sha256', $uid);
		$count = $cache->inc($key);
		if (!is_int($count)) {
			return null;
		}
		if ($count === 1) {
			// Some caches create counters without a lifetime.
			$cache->set($key, 1, DirectoryScraping::WINDOW + 60);
		}
		// The default when the stored value is out of range.
		$limit = $this->settings->paramInt(DirectoryScraping::ID, $limitDefinition[0]);
		if ($count <= $limit) {
			return null;
		}
		return $this->exceeded($uid, $group, $count, $limit, ($bucket + 1) * DirectoryScraping::WINDOW, $now);
	}

	private function exceeded(string $uid, string $group, int $count, int $limit, int $until, int $now): ?SessionBlock {
		$mode = $this->settings->modeState(DirectoryScraping::ID);
		if (!$mode->runs()) {
			return null;
		}
		if ($count === $limit + 1) {
			$this->record($uid, $group, $count, $limit, $until);
		}
		if (!$mode->acts() || !$this->settings->hasResponse(DirectoryScraping::ID, ResponseType::RateLimit)) {
			return null;
		}
		return SessionBlock::rateLimited(
			'directory_rate_limited',
			'Too many requests of this kind. Try again later.',
			$until - $now,
		);
	}

	private function record(string $uid, string $group, int $count, int $limit, int $until): void {
		$this->container->get(ResponseEngine::class)->handle(new DetectionDraft(
			checkId: DirectoryScraping::ID,
			source: $this->container->get(RemoteAddressResolver::class)->current(),
			uid: $uid,
			facts: [
				'group' => $group,
				'count' => $count,
				'limit' => $limit,
				'window' => DirectoryScraping::WINDOW,
				'until' => $until,
			],
			merge: DetectionDraft::MERGE_USER,
			userAgent: $this->container->get(IRequest::class)->getHeader('User-Agent'),
			sessionTokenId: $this->container->get(CurrentSession::class)->tokenId(),
		));
	}

	/**
	 * Whether the check may run: two reads of the app config, which is
	 * loaded for the request anyway. The address check runs first and only
	 * hands on a verdict while the app is enabled; learning mode and the
	 * memory cache are applied when a limit is reached.
	 */
	private function runs(): bool {
		return ($this->context->verdict() !== null || $this->settings->isEnabled())
			&& $this->settings->configuredMode(DirectoryScraping::ID) !== Mode::Off;
	}
}
