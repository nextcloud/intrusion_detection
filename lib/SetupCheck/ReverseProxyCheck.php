<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SetupCheck;

use OCA\IntrusionDetection\Db\LoginMapper;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Notification\AdminLinks;
use OCP\IConfig;
use OCP\IL10N;
use OCP\IURLGenerator;

/**
 * Several different people logged in from one private address while no
 * trusted proxy is configured: Nextcloud most likely sees the reverse proxy
 * instead of the visitors. Blocks of that address are then paused by the
 * safety valve, so attacks through the proxy cannot be blocked.
 */
class ReverseProxyCheck extends ProblemCheck {
	/** How many of the latest logins are looked at */
	public const SAMPLE = 50;
	/** Different accounts from one private address that make it look like a proxy */
	public const MIN_USERS = 3;

	public function __construct(
		IL10N $l,
		AdminLinks $links,
		private readonly LoginMapper $logins,
		private readonly IConfig $config,
		private readonly IURLGenerator $urlGenerator,
	) {
		parent::__construct($l, $links);
	}

	#[\Override]
	public function getName(): string {
		return $this->l->t('Intrusion detection: reverse proxy');
	}

	#[\Override]
	protected function fine(): string {
		return $this->l->t('Nextcloud sees the addresses of its visitors.');
	}

	#[\Override]
	public function finding(IL10N $l): ?Finding {
		$proxies = $this->config->getSystemValue('trusted_proxies', []);
		if (is_array($proxies) && $proxies !== []) {
			return null;
		}
		/** @var array<string, array<string, true>> $users */
		$users = [];
		foreach ($this->logins->recent(self::SAMPLE) as $row) {
			$users[$row['ipKey']][$row['uid']] = true;
		}
		$suspect = null;
		$most = 0;
		foreach ($users as $ipKey => $accounts) {
			$source = SourceKey::tryFromIpKey($ipKey);
			if ($source === null || count($accounts) < self::MIN_USERS || count($accounts) <= $most || !self::isPrivate($source)) {
				continue;
			}
			$suspect = $source->ip;
			$most = count($accounts);
		}
		if ($suspect === null) {
			return null;
		}
		return new Finding(
			'reverse_proxy',
			Finding::LEVEL_WARNING,
			$l->t('Every visitor seems to come from %s', [$suspect]),
			$l->t('%1$s of the last %2$s logins by different people came from %3$s, a private address, and no trusted proxies are configured. Nextcloud probably sees your reverse proxy instead of the visitors, so it cannot tell them apart. Blocks of this address are paused, because they would lock everyone out.', [(string)$most, (string)self::SAMPLE, $suspect]),
			$l->t('Add the address of your reverse proxy to "trusted_proxies" in config.php. If the proxy sends the visitor\'s address in another header than X-Forwarded-For, also set "forwarded_for_headers".'),
			$this->urlGenerator->linkToDocs('admin-reverse-proxy'),
			$l->t('Reverse proxy documentation'),
		);
	}

	private static function isPrivate(SourceKey $source): bool {
		return $source->isLoopback()
			|| filter_var($source->ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
	}
}
