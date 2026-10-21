<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SetupCheck;

use OCA\IntrusionDetection\Notification\AdminLinks;
use OCP\IConfig;
use OCP\IL10N;
use OCP\IURLGenerator;

/**
 * Core's brute-force protection is switched off. Intrusion detection
 * recognises attacks the throttle cannot see, but does not replace it.
 */
class BruteForceProtectionCheck extends ProblemCheck {
	public function __construct(
		IL10N $l,
		AdminLinks $links,
		private readonly IConfig $config,
		private readonly IURLGenerator $urlGenerator,
	) {
		parent::__construct($l, $links);
	}

	#[\Override]
	public function getName(): string {
		return $this->l->t('Intrusion detection: brute-force protection');
	}

	#[\Override]
	protected function fine(): string {
		return $this->l->t('Brute-force protection is on.');
	}

	#[\Override]
	public function finding(IL10N $l): ?Finding {
		if ($this->config->getSystemValueBool('auth.bruteforce.protection.enabled', true)) {
			return null;
		}
		return new Finding(
			'bruteforce_off',
			Finding::LEVEL_INFO,
			$l->t('Brute-force protection is off'),
			$l->t('Nextcloud\'s brute-force protection slows down password guessing from one address. Intrusion detection recognises the attacks it cannot see, such as botnets, but it does not slow down every guess.'),
			$l->t('Remove "auth.bruteforce.protection.enabled" from config.php, or set it to true.'),
			$this->urlGenerator->linkToDocs('admin-security'),
			$l->t('Security documentation'),
		);
	}
}
