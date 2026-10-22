<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\SetupCheck;

use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Notification\AdminLinks;
use OCP\IL10N;

/**
 * Administrators log in from the trusted networks only, but there are no
 * trusted networks: every administrator login needs confirmation, from
 * anywhere. Administrators who cannot confirm are reported by
 * {@see AdminContactCheck}.
 */
class AdminNetworksCheck extends ProblemCheck {
	public function __construct(
		IL10N $l,
		AdminLinks $links,
		private readonly Settings $settings,
	) {
		parent::__construct($l, $links);
	}

	#[\Override]
	public function getName(): string {
		return $this->l->t('Intrusion detection: trusted networks for administrators');
	}

	#[\Override]
	protected function fine(): string {
		return $this->settings->getBool(GlobalSettings::ADMIN_TRUSTED_NETWORKS_ONLY)
			? $this->l->t('Administrators log in from the trusted networks only.')
			: $this->l->t('Administrators may log in from any network.');
	}

	#[\Override]
	public function finding(IL10N $l): ?Finding {
		if (!$this->settings->getBool(GlobalSettings::ADMIN_TRUSTED_NETWORKS_ONLY)) {
			return null;
		}
		$networks = $this->settings->global(GlobalSettings::RISKY_NETWORK_OFFICE_NETWORKS);
		if (is_array($networks) && $networks !== []) {
			return null;
		}
		return new Finding(
			'admin_networks_empty',
			Finding::LEVEL_WARNING,
			$l->t('No trusted networks for administrators'),
			$l->t('Administrators log in from trusted networks only, but there are no trusted networks yet, so every administrator login from anywhere needs confirmation.'),
			$l->t('Add your office and VPN networks to the trusted networks, or turn "Administrators log in from trusted networks only" off.'),
			'#settings-confirmation',
			$l->t('Open the login confirmation settings'),
		);
	}
}
