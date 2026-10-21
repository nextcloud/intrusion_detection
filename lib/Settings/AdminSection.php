<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Settings;

use OCA\IntrusionDetection\AppInfo\Application;
use OCP\IL10N;
use OCP\IURLGenerator;
use OCP\Settings\IIconSection;

/**
 * "Intrusion detection" in the administration settings, right after Security.
 */
class AdminSection implements IIconSection {
	public function __construct(
		private readonly IURLGenerator $urlGenerator,
		private readonly IL10N $l,
	) {
	}

	#[\Override]
	public function getID(): string {
		return Application::APP_ID;
	}

	#[\Override]
	public function getName(): string {
		return $this->l->t('Intrusion detection');
	}

	#[\Override]
	public function getPriority(): int {
		// Security has 10.
		return 11;
	}

	#[\Override]
	public function getIcon(): string {
		return $this->urlGenerator->imagePath(Application::APP_ID, 'app-dark.svg');
	}
}
