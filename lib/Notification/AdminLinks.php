<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Notification;

use OCA\IntrusionDetection\AppInfo\Application;
use OCP\IURLGenerator;

/**
 * Absolute links into the admin page, for notifications and emails. They
 * never carry a token: the page itself checks that the reader is an admin.
 */
class AdminLinks {
	public function __construct(
		private readonly IURLGenerator $urlGenerator,
	) {
	}

	public function adminPage(): string {
		return $this->urlGenerator->linkToRouteAbsolute('settings.AdminSettings.index', ['section' => Application::APP_ID]);
	}

	public function detection(int $id): string {
		return $this->adminPage() . '#detection-' . $id;
	}

	public function icon(): string {
		return $this->urlGenerator->getAbsoluteURL($this->urlGenerator->imagePath(Application::APP_ID, 'app-dark.svg'));
	}
}
