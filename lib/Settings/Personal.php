<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Settings;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\KnownDevice\KnownDevices;
use OCA\IntrusionDetection\Personal\PersonalOverview;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\AppFramework\Services\IInitialState;
use OCP\IL10N;
use OCP\IUserSession;
use OCP\Settings\ISettings;
use OCP\Util;

/**
 * The user's own security events in personal settings → Security, right
 * after core's list of devices and sessions (concept section 15.1). The
 * overview comes with the page; the lists are loaded from the personal API.
 * Nothing is shown while `personal_page_enabled` is off.
 */
class Personal implements ISettings {
	/** Core's devices and sessions have 100 */
	public const PRIORITY = 110;

	public function __construct(
		private readonly Settings $settings,
		private readonly PersonalOverview $overview,
		private readonly KnownDevices $knownDevices,
		private readonly IUserSession $userSession,
		private readonly IInitialState $initialState,
		private readonly IL10N $l,
	) {
	}

	public function isVisible(): bool {
		return $this->settings->personalPageEnabled();
	}

	#[\Override]
	public function getForm(): TemplateResponse {
		$user = $this->userSession->getUser();
		if ($user === null || !$this->isVisible()) {
			return new TemplateResponse('settings', 'settings/empty', [], '');
		}
		$this->initialState->provideInitialState('personal', [
			'overview' => $this->overview->get($user, $this->l),
			'knownDevicesEnabled' => $this->knownDevices->isEnabled(),
		]);
		Util::addStyle(Application::APP_ID, 'settings-personal');
		Util::addScript(Application::APP_ID, 'settings-personal');
		return new TemplateResponse(Application::APP_ID, 'settings-personal', renderAs: '');
	}

	#[\Override]
	public function getSection(): string {
		return 'security';
	}

	#[\Override]
	public function getPriority(): int {
		return self::PRIORITY;
	}
}
