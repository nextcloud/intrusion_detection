<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Notification;

use OCP\IURLGenerator;

/**
 * The only link the app puts into what it tells users: their own security
 * settings. It never carries a token or an id; the page shows what belongs
 * to whoever is logged in.
 */
class UserLinks {
	public const ANCHOR = 'intrusion-detection';

	public function __construct(
		private readonly IURLGenerator $urlGenerator,
	) {
	}

	public function securityPage(): string {
		return $this->urlGenerator->linkToRouteAbsolute('settings.PersonalSettings.index', ['section' => 'security']) . '#' . self::ANCHOR;
	}
}
