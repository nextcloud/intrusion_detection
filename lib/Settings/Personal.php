<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Settings;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Personal\ManageSummary;
use OCA\IntrusionDetection\Personal\PersonalOverview;
use OCA\IntrusionDetection\StaleCredential\StaleCredentials;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\AppFramework\Services\IInitialState;
use OCP\IL10N;
use OCP\IUserSession;
use OCP\Settings\ISettings;
use OCP\Util;

/**
 * The user's own security events in personal settings → Security, right
 * after core's list of devices and sessions (concept section 15.1). The
 * overview, what "Manage" offers and the app passwords and devices unused
 * for 90 days come with the page; the activity and the lists are loaded
 * from the personal API.
 * Nothing is shown while `personal_page_enabled` is off.
 */
class Personal implements ISettings {
	/** Core's devices and sessions have 100 */
	public const PRIORITY = 110;

	public function __construct(
		private readonly AppSettings $settings,
		private readonly PersonalOverview $overview,
		private readonly IUserSession $userSession,
		private readonly IInitialState $initialState,
		private readonly IL10N $l,
		private readonly ManageSummary $manage,
		private readonly StaleCredentials $staleCredentials,
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
			'manage' => $this->manage->forUser($user->getUID(), $this->l),
			'staleCredentials' => $this->staleCredentials->forUser($user->getUID(), $this->l),
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
