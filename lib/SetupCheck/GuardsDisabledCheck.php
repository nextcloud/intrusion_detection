<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SetupCheck;

use OCA\IntrusionDetection\Guard\AddressGuard;
use OCA\IntrusionDetection\Notification\AdminLinks;
use OCP\IConfig;
use OCP\IL10N;

/**
 * The emergency switch in config.php ({@see AddressGuard::DISABLE_SWITCH})
 * turns every request guard off: no block, blocklist, trap URL, injection
 * probe or stolen credential is stopped while it is set.
 */
class GuardsDisabledCheck extends ProblemCheck {
	public function __construct(
		IL10N $l,
		AdminLinks $links,
		private readonly IConfig $config,
	) {
		parent::__construct($l, $links);
	}

	#[\Override]
	public function getName(): string {
		return $this->l->t('Intrusion detection: request guards');
	}

	#[\Override]
	protected function fine(): string {
		return $this->l->t('The request guards are on.');
	}

	#[\Override]
	public function finding(IL10N $l): ?Finding {
		if (!$this->config->getSystemValueBool(AddressGuard::DISABLE_SWITCH, false)) {
			return null;
		}
		return new Finding(
			'guards_disabled',
			Finding::LEVEL_ERROR,
			$l->t('The request guards are switched off in config.php'),
			$l->t('"intrusion_detection.disable_guards" is set in config.php. No request is checked: blocked addresses, blocklists, trap URLs, injection probes and stolen credentials all pass. The checks that look at logins still run.'),
			$l->t('Remove "intrusion_detection.disable_guards" from config.php once the problem it was set for is solved.'),
		);
	}
}
