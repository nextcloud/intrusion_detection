<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SetupCheck;

use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Notification\AdminLinks;
use OCP\IL10N;

/**
 * Tells that config.php locks the protective settings
 * ({@see AppSettings::LOCK}), so that nobody wonders why they cannot be
 * changed on the admin page or with occ.
 */
class ConfigLockCheck extends ProblemCheck {
	public function __construct(
		IL10N $l,
		AdminLinks $links,
		private readonly AppSettings $settings,
	) {
		parent::__construct($l, $links);
	}

	#[\Override]
	public function getName(): string {
		return $this->l->t('Intrusion detection: locked settings');
	}

	#[\Override]
	protected function fine(): string {
		return $this->l->t('The protective settings are not locked in config.php. Administrators can switch intrusion detection, the admin change alerts and the approval of new administrators off; each such change is reported.');
	}

	#[\Override]
	public function finding(IL10N $l): ?Finding {
		if (!$this->settings->isLocked()) {
			return null;
		}
		return new Finding(
			'settings_locked',
			Finding::LEVEL_INFO,
			$l->t('Protective settings are locked in config.php'),
			$l->t('"intrusion_detection.locked" is set in config.php. Intrusion detection stays on, the admin change alerts stay in Protect, and a second administrator must approve every new administrator. Neither the admin page nor occ can change that, and new administrators added with occ do not wait for approval.'),
			$l->t('To change these settings, remove "intrusion_detection.locked" from config.php.'),
		);
	}
}
