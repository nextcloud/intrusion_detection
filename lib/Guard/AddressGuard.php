<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Guard;

use OCA\IntrusionDetection\Address\AddressCache;
use OCA\IntrusionDetection\Address\AddressResolver;
use OCA\IntrusionDetection\Address\Verdict;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Perf\GuardTimer;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IConfig;
use OCP\IRequest;
use OCP\Security\Guard\GuardDecision;
use OCP\Security\Guard\IRequestGuard;

/**
 * The one per-request address check, for blocks and blocklists.
 *
 * On the common path it costs two memory-cache gets: the cache version and
 * the verdict for the address. Only on a cold cache does it ask the database.
 */
class AddressGuard implements IRequestGuard {
	/** config.php switch that turns every guard off without touching the database */
	public const DISABLE_SWITCH = 'intrusion_detection.disable_guards';

	public function __construct(
		private readonly IConfig $config,
		private readonly Settings $settings,
		private readonly AddressCache $cache,
		private readonly AddressResolver $resolver,
		private readonly RemoteAddressResolver $addresses,
		private readonly RequestContext $context,
		private readonly ITimeFactory $timeFactory,
		private readonly GuardTimer $timer,
	) {
	}

	#[\Override]
	public function check(IRequest $request): ?GuardDecision {
		$start = $this->timer->start();
		try {
			return $this->decisionFor($request->getRemoteAddress());
		} finally {
			$this->timer->stop($start);
		}
	}

	/**
	 * The guard's decision for a client address. Used by check() and by
	 * occ intrusion:benchmark.
	 */
	public function decisionFor(string $remoteAddress): ?GuardDecision {
		if ($this->config->getSystemValueBool(self::DISABLE_SWITCH, false) || !$this->settings->isEnabled()) {
			return null;
		}
		$source = SourceKey::tryFromIp($remoteAddress);
		if ($source === null) {
			return null;
		}
		$now = $this->timeFactory->getTime();
		$verdict = $this->verdict($source, $now);
		$this->context->setVerdict($verdict);
		if (!$verdict->isDenied($now)) {
			return null;
		}
		// The allowlist wins over every block. Checked only here, on the rare
		// denied path, so it costs nothing on normal requests.
		if ($this->addresses->isIgnored($source)) {
			return null;
		}
		return GuardDecision::deny($verdict->denyUntil - $now, $verdict->reference);
	}

	private function verdict(SourceKey $source, int $now): Verdict {
		$verdict = $this->cache->get($source);
		if ($verdict !== null && $verdict->cacheUntil > $now) {
			return $verdict;
		}
		$verdict = $this->resolver->resolve($source);
		$this->cache->set($source, $verdict, $now);
		return $verdict;
	}
}
