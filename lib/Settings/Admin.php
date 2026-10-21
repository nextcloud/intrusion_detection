<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Settings;

use OCA\IntrusionDetection\Admin\CheckList;
use OCA\IntrusionDetection\Admin\GlobalSettingsPresenter;
use OCA\IntrusionDetection\Admin\StatusService;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\AppFramework\Services\IInitialState;
use OCP\IL10N;
use OCP\IURLGenerator;
use OCP\Settings\ISettings;
use OCP\Util;

/**
 * The admin page. The status, the checks and the settings come with the
 * page, so it shows at once; everything else is loaded from the admin API.
 */
class Admin implements ISettings {
	public function __construct(
		private readonly StatusService $status,
		private readonly CheckList $checks,
		private readonly GlobalSettingsPresenter $globalSettings,
		private readonly RemoteAddressResolver $addresses,
		private readonly IInitialState $initialState,
		private readonly IURLGenerator $urlGenerator,
		private readonly IL10N $l,
	) {
	}

	#[\Override]
	public function getForm(): TemplateResponse {
		$this->initialState->provideInitialState('admin', [
			'status' => $this->status->status($this->l),
			'checks' => $this->checks->all($this->l),
			'settings' => $this->globalSettings->present($this->l),
			'ownAddress' => $this->addresses->current()?->ip,
			'docUrl' => $this->urlGenerator->linkToDocs('admin-intrusion-detection'),
			'bruteForceSettingsUrl' => $this->urlGenerator->linkToRoute('settings.AdminSettings.index', ['section' => 'security']),
		]);
		Util::addStyle(Application::APP_ID, 'settings-admin');
		Util::addScript(Application::APP_ID, 'settings-admin');
		return new TemplateResponse(Application::APP_ID, 'settings-admin', renderAs: '');
	}

	#[\Override]
	public function getSection(): string {
		return Application::APP_ID;
	}

	#[\Override]
	public function getPriority(): int {
		return 10;
	}
}
