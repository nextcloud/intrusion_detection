<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SetupCheck;

use OCA\IntrusionDetection\AdminChange\ConfigWatch;
use OCA\IntrusionDetection\Decoy\DecoyService;
use OCA\IntrusionDetection\Notification\AdminLinks;
use OCA\IntrusionDetection\State\AppState;
use OCP\IL10N;

/**
 * Decoys created before the instance secret changed: their secrets are
 * kept as fingerprints keyed with the old secret, so a use of the secret
 * no longer matches, only a use of the login name.
 */
class DecoySecretCheck extends ProblemCheck {
	public function __construct(
		IL10N $l,
		AdminLinks $links,
		private readonly DecoyService $decoys,
		private readonly AppState $state,
	) {
		parent::__construct($l, $links);
	}

	#[\Override]
	public function getName(): string {
		return $this->l->t('Intrusion detection: decoys');
	}

	#[\Override]
	protected function fine(): string {
		return $this->l->t('Every decoy matches its secret.');
	}

	#[\Override]
	public function finding(IL10N $l): ?Finding {
		$stale = $this->decoys->countCreatedBefore($this->state->getInt(ConfigWatch::SECRET_CHANGED_STATE));
		if ($stale === 0) {
			return null;
		}
		return new Finding(
			'decoy_secret_changed',
			Finding::LEVEL_WARNING,
			$l->t('Decoys no longer match their secret'),
			$l->n('%n decoy was created before the "secret" in config.php changed. Its secret no longer matches, so only its login name is noticed.', '%n decoys were created before the "secret" in config.php changed. Their secrets no longer match, so only their login names are noticed.', $stale),
			$l->t('Delete these decoys and create new ones, then plant the new secrets where the old ones were.'),
			'#decoys',
			$l->t('Open the decoys'),
		);
	}
}
