<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Config;

use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffing;
use OCA\IntrusionDetection\Check\Checks\DirectoryScraping;
use OCA\IntrusionDetection\Check\Checks\InjectionProbe;
use OCA\IntrusionDetection\Check\Checks\TrapUrl;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Keys;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Config\Prerequisites;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Definition\InvalidParamException;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IAppConfig;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;

/**
 * Reads take their definitions from the generated lexicon data: they build no
 * check and no global setting definition, except for the two settings whose
 * items need a validator of their own.
 */
class SettingsReadTest extends TestCase {
	private IAppConfig&MockObject $appConfig;
	private CheckRegistry&MockObject $registry;
	private GlobalSettings $globals;
	private Prerequisites&MockObject $prerequisites;
	private Settings $settings;
	/** @var array<string, mixed> */
	private array $stored = [];

	protected function setUp(): void {
		parent::setUp();
		$this->appConfig = $this->createMock(IAppConfig::class);
		foreach (['getValueInt', 'getValueFloat', 'getValueBool', 'getValueString', 'getValueArray'] as $method) {
			$this->appConfig->method($method)->willReturnCallback(fn (string $app, string $key, mixed $default): mixed => $this->stored[$key] ?? $default);
		}
		$this->registry = $this->createMock(CheckRegistry::class);
		$this->globals = new GlobalSettings();
		$this->prerequisites = $this->createMock(Prerequisites::class);
		$this->prerequisites->method('isMet')->willReturn(true);
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturn(1_800_000_000);
		$this->settings = new Settings($this->appConfig, $this->registry, $time, $this->prerequisites, $this->globals, $this->createMock(IEventDispatcher::class));
	}

	public function testCommonReadsBuildNoDefinitions(): void {
		$this->registry->expects($this->never())->method($this->anything());

		$this->assertTrue($this->settings->isEnabled());
		$this->assertSame(0, $this->settings->getInt(GlobalSettings::LEARNING_UNTIL));
		$this->assertSame(Mode::Protect, $this->settings->configuredMode(TrapUrl::ID));
		$this->assertSame(Mode::Protect, $this->settings->effectiveMode(TrapUrl::ID));
		$this->assertTrue($this->settings->paramBool(TrapUrl::ID, 'builtin_enabled'));
		$this->assertSame(600, $this->settings->paramInt(CredentialStuffing::ID, 'window'));
		$this->assertContains(ResponseType::Ban, $this->settings->responses(CredentialStuffing::ID));
		$this->assertArrayHasKey('window', $this->settings->params(CredentialStuffing::ID));
		$this->assertNull((new \ReflectionProperty(GlobalSettings::class, 'definitions'))->getValue($this->globals), 'no global setting definition was built');
	}

	public function testStoredValuesOutsideTheirRangeReadAsTheDefault(): void {
		$this->stored[Keys::param(CredentialStuffing::ID, 'window')] = 5;
		$this->stored[GlobalSettings::NOTIFY_ADMIN_EMAIL_MIN_SEVERITY] = 'nonsense';
		$this->assertSame(600, $this->settings->paramInt(CredentialStuffing::ID, 'window'));
		$this->assertSame('high', $this->settings->global(GlobalSettings::NOTIFY_ADMIN_EMAIL_MIN_SEVERITY));
	}

	public function testResponsesTheCheckDoesNotAllowAreDropped(): void {
		$this->stored[Keys::responses(TrapUrl::ID)] = [ResponseType::Ban->value, ResponseType::ForcePasswordChange->value, 'nonsense'];
		$this->assertSame([ResponseType::Ban], $this->settings->responses(TrapUrl::ID));
	}

	public function testRequirementsAndLearningModeComeFromTheStaticData(): void {
		$prerequisites = $this->createMock(Prerequisites::class);
		$prerequisites->method('isMet')->willReturn(false);
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturn(1_800_000_000);
		$settings = new Settings($this->appConfig, $this->registry, $time, $prerequisites, $this->globals, $this->createMock(IEventDispatcher::class));
		$this->assertSame(ModeState::REASON_REQUIREMENT, $settings->modeState(DirectoryScraping::ID)->reason);

		$this->stored[GlobalSettings::LEARNING_UNTIL] = 1_800_000_100;
		$this->assertSame(Mode::Observe, $this->settings->effectiveMode(CredentialStuffing::ID));
	}

	public function testAParameterWithAnItemValidatorUsesTheFullDefinition(): void {
		$definition = (new InjectionProbe())->definition();
		$this->registry->expects($this->once())->method('get')->with(InjectionProbe::ID)->willReturn($definition);
		$this->assertSame([], $this->settings->paramList(InjectionProbe::ID, InjectionProbe::PARAM_CUSTOM));
		$this->assertSame([], $this->settings->paramList(InjectionProbe::ID, InjectionProbe::PARAM_CUSTOM), 'the definition is kept for the request');
	}

	public function testUnknownChecksAndSettingsThrow(): void {
		$this->expectException(InvalidParamException::class);
		$this->settings->configuredMode('no_such_check');
	}

	public function testUnknownGlobalSettingsThrow(): void {
		$this->expectException(InvalidParamException::class);
		$this->settings->global('no_such_setting');
	}
}
