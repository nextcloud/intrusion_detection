<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SetupCheck;

use OCA\IntrusionDetection\Address\AddressResolver;
use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Notification\AdminLinks;
use OCP\IL10N;
use OCP\IURLGenerator;

/**
 * No memory cache: the address check asks the database on every request.
 * The finding measures what that costs right now, with an address from the
 * documentation range.
 */
class MemoryCacheCheck extends ProblemCheck {
	public const PROBE_ADDRESS = '198.51.100.1';
	private const ROUNDS = 3;

	public function __construct(
		IL10N $l,
		AdminLinks $links,
		private readonly Caches $caches,
		private readonly AddressResolver $resolver,
		private readonly IURLGenerator $urlGenerator,
	) {
		parent::__construct($l, $links);
	}

	#[\Override]
	public function getName(): string {
		return $this->l->t('Intrusion detection: memory cache');
	}

	#[\Override]
	protected function fine(): string {
		return $this->l->t('A memory cache keeps the address check off the database.');
	}

	#[\Override]
	public function finding(IL10N $l): ?Finding {
		if ($this->caches->isAvailable()) {
			return null;
		}
		$milliseconds = $this->measure();
		return new Finding(
			'memory_cache_missing',
			Finding::LEVEL_INFO,
			$l->t('No memory cache is configured'),
			$milliseconds === null
				? $l->t('Without a memory cache, every request asks the database whether its address is blocked. Checks that need a memory cache cannot run.')
				: $l->t('Without a memory cache, every request asks the database whether its address is blocked: about %s ms per request, measured just now. Checks that need a memory cache cannot run.', [number_format($milliseconds, 2)]),
			$l->t('Configure APCu as "memcache.local" in config.php, and Redis as "memcache.distributed" when several web servers share the work.'),
			$this->urlGenerator->linkToDocs('admin-performance'),
			$l->t('Memory cache documentation'),
		);
	}

	/**
	 * The median time of a few address checks, in milliseconds.
	 */
	private function measure(): ?float {
		$source = SourceKey::fromIp(self::PROBE_ADDRESS);
		$times = [];
		try {
			for ($i = 0; $i < self::ROUNDS; $i++) {
				$start = hrtime(true);
				$this->resolver->resolve($source);
				$times[] = (hrtime(true) - $start) / 1e6;
			}
		} catch (\Throwable) {
			return null;
		}
		sort($times);
		return $times[intdiv(count($times), 2)];
	}
}
