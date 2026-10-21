<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Admin;

use OCA\IntrusionDetection\Admin\GlobalSettingsPresenter;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCP\L10N\IFactory;
use OCP\Server;
use Test\TestCase;

class GlobalSettingsPresenterTest extends TestCase {
	public function testInternalStateIsNeverPresentedOrEditable(): void {
		$globals = new GlobalSettings();
		$settings = $this->createMock(Settings::class);
		$settings->method('global')->willReturnCallback(static fn (string $name): int|float|bool|string|array => $globals->get($name)?->default ?? 0);
		$presenter = new GlobalSettingsPresenter($globals, $settings);
		$l = Server::get(IFactory::class)->get('intrusion_detection', 'en');

		$presented = $presenter->present($l);
		$names = array_column($presented['settings'], 'name');

		foreach (array_keys($globals->all()) as $name) {
			$hidden = GlobalSettings::isInternal($name) || GlobalSettings::isUnlisted($name)
				|| in_array($name, [GlobalSettings::LEARNING_UNTIL, GlobalSettings::BLOCKLIST_SOURCES], true);
			$this->assertSame(!$hidden, in_array($name, $names, true), $name);
			$this->assertSame(!$hidden, $presenter->isEditable($name), $name);
		}
		$this->assertFalse($presenter->isEditable('no_such_setting'));

		foreach ($presented['settings'] as $setting) {
			$this->assertNotSame(ucfirst(str_replace('_', ' ', $setting['name'])), $setting['label'], $setting['name'] . ' has a real label');
			$this->assertNotSame(GlobalSettingsPresenter::GROUP_OTHER, $setting['group'], $setting['name'] . ' belongs to a group');
		}

		foreach ($presented['templates'] as $template) {
			preg_match_all('/\{([a-z0-9_]+)\}/', $template, $m);
			foreach ($m[1] as $placeholder) {
				$this->assertContains($placeholder, $names, 'templates only use settings the page has');
			}
		}
	}
}
