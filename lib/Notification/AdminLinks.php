<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Notification;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Db\Approval;
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
		$path = $this->urlGenerator->linkToRoute('settings.AdminSettings.index', ['section' => Application::APP_ID]);
		// In a request guard the apps' routes are not loaded yet, and the router returns nothing.
		if ($path === '') {
			$path = rtrim($this->urlGenerator->linkTo('', 'index.php'), '/') . '/settings/admin/' . Application::APP_ID;
		}
		return $this->urlGenerator->getAbsoluteURL($path);
	}

	public function detection(string $id): string {
		return $this->adminPage() . '#detection-' . $id;
	}

	/**
	 * The recap of the learning period that ended last, on the overview.
	 */
	public function learningRecap(): string {
		return $this->adminPage() . '#overview-recap';
	}

	public function approval(string $id): string {
		return $this->adminPage() . '#approval-' . $id;
	}

	/**
	 * Where an administrator decides on a request: the waiting logins in the
	 * settings, or the request's own card on the overview.
	 */
	public function decide(Approval $approval): string {
		return $approval->getKind() === Approval::KIND_LOGIN
			? $this->adminPage() . '#settings-approvals'
			: $this->approval((string)$approval->getId());
	}

	public function icon(): string {
		return $this->urlGenerator->getAbsoluteURL($this->urlGenerator->imagePath(Application::APP_ID, 'app-dark.svg'));
	}
}
