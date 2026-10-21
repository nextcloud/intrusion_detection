<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SetupCheck;

use OCA\IntrusionDetection\Net\ProxySuspect;
use OCA\IntrusionDetection\Notification\AdminLinks;
use OCP\IL10N;
use OCP\IURLGenerator;

/**
 * Several different people logged in from one private address while no
 * trusted proxy is configured: Nextcloud most likely sees the reverse proxy
 * instead of the visitors. The ban service then does not block that
 * address ({@see \OCA\IntrusionDetection\Response\BanService}), so attacks
 * through the proxy cannot be blocked.
 */
class ReverseProxyCheck extends ProblemCheck {
	public function __construct(
		IL10N $l,
		AdminLinks $links,
		private readonly ProxySuspect $proxies,
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
		$suspect = $this->proxies->suspect();
		if ($suspect === null) {
			return null;
		}
		[$source, $most] = $suspect;
		return new Finding(
			'reverse_proxy',
			Finding::LEVEL_WARNING,
			$l->t('All visitors share one address – reverse proxy?'),
			$l->t('%1$s of the last %2$s logins by different people came from %3$s, a private address, and no trusted proxies are configured. Nextcloud probably sees your reverse proxy instead of the visitors, so it cannot tell them apart. Blocks of this address are paused, because they would lock everyone out.', [(string)$most, (string)ProxySuspect::SAMPLE, $source->ip]),
			$l->t('Add the address of your reverse proxy to "trusted_proxies" in config.php. If the proxy sends the visitor\'s address in another header than X-Forwarded-For, also set "forwarded_for_headers".'),
			$this->urlGenerator->linkToDocs('admin-reverse-proxy'),
			$l->t('Reverse proxy documentation'),
		);
	}

}
