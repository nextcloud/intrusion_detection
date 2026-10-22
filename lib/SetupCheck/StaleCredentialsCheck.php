<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SetupCheck;

use OCA\IntrusionDetection\Notification\AdminLinks;
use OCA\IntrusionDetection\StaleCredential\StaleCredentials;
use OCA\IntrusionDetection\StaleCredential\StaleCredentialSweep;
use OCP\IL10N;

/**
 * A tip: app passwords and remembered browsers nobody used for 90 days,
 * across all accounts. A thief who finds one can use it unnoticed. The
 * counts come from the daily look ({@see StaleCredentialSweep}); this
 * check only reads them.
 */
class StaleCredentialsCheck extends ProblemCheck {
	public function __construct(
		IL10N $l,
		AdminLinks $links,
		private readonly StaleCredentialSweep $sweep,
	) {
		parent::__construct($l, $links);
	}

	#[\Override]
	public function getName(): string {
		return $this->l->t('Unused app passwords and devices');
	}

	#[\Override]
	protected function fine(): string {
		return $this->l->t('Every app password and remembered browser was used in the last %s days.', [(string)StaleCredentials::DAYS]);
	}

	#[\Override]
	public function finding(IL10N $l): ?Finding {
		['credentials' => $credentials, 'accounts' => $accounts] = $this->sweep->counts();
		if ($credentials === 0) {
			return null;
		}
		$fix = $this->sweep->removeDays() === 0
			? $l->t('Users see them in their security settings and are reminded at most once a month. To remove them, run occ intrusion:credentials:stale --revoke, or switch on their automatic removal.')
			: $l->n('They are removed automatically after %n day without use.', 'They are removed automatically after %n days without use.', $this->sweep->removeDays());
		return new Finding(
			'stale_credentials',
			Finding::LEVEL_INFO,
			$l->n('%n app password or device has not been used for 3 months', '%n app passwords and devices have not been used for 3 months', $credentials),
			$l->n(
				'%n account has app passwords or remembered browsers that nobody used for %s days. If someone else had one of them, nobody would notice.',
				'%n accounts have app passwords or remembered browsers that nobody used for %s days. If someone else had one of them, nobody would notice.',
				$accounts,
				[(string)StaleCredentials::DAYS],
			),
			$fix,
			'#settings-privacy',
			$l->t('Open the setting'),
		);
	}
}
