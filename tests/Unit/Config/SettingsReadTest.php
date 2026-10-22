<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Config;

use OCA\IntrusionDetection\Check\Checks\CredentialStuffing;
use OCA\IntrusionDetection\Check\Checks\DirectoryScraping;
use OCA\IntrusionDetection\Check\Checks\InjectionProbe;
use OCA\IntrusionDetection\Check\Checks\TrapUrl;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Keys;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Config\Prerequisites;
use OCA\IntrusionDetection\Definition\InvalidParamException;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IAppConfig;
use Test\TestCase;

/**
 * Reads take their definitions from the generated lexicon data: they need
 * no check registry and no global setting definition.
 */
class SettingsReadTest extends TestCase {
	/** @var array<string, mixed> */
	private array $stored = [];

	public function testCommonReadsBuildNoDefinitions(): void {
		foreach ([AppSettings::class, CheckSettings::class] as $class) {
			$types = array_map(static fn (\ReflectionParameter $p): string => (string)$p->getType(), (new \ReflectionMethod($class, '__construct'))->getParameters());
			$this->assertSame([], array_values(array_filter($types, static fn (string $type): bool => !str_starts_with($type, 'OCP\\') && !in_array($type, [AppSettings::class, Prerequisites::class], true))), $class . ' builds nothing to read');
		}

		$app = $this->app();
		$checks = $this->checks();
		$this->assertTrue($app->isEnabled());
		$this->assertSame(0, $app->learningUntil());
		$this->assertSame(Mode::Protect, $checks->configuredMode(TrapUrl::ID));
		$this->assertSame(Mode::Protect, $checks->effectiveMode(TrapUrl::ID));
		$this->assertTrue($checks->paramBool(TrapUrl::ID, 'builtin_enabled'));
		$this->assertSame(600, $checks->paramInt(CredentialStuffing::ID, 'window'));
		$this->assertContains(ResponseType::Ban, $checks->responses(CredentialStuffing::ID));
		$this->assertArrayHasKey('window', $checks->params(CredentialStuffing::ID));
	}

	public function testStoredValuesOutsideTheirRangeReadAsTheDefault(): void {
		$this->stored[Keys::param(CredentialStuffing::ID, 'window')] = 5;
		$this->stored[GlobalSettings::NOTIFY_ADMIN_EMAIL_MIN_SEVERITY] = 'nonsense';
		$this->assertSame(600, $this->checks()->paramInt(CredentialStuffing::ID, 'window'));
		$this->assertSame('high', $this->app()->notifyAdminEmailMinSeverity());
	}

	public function testResponsesTheCheckDoesNotAllowAreDropped(): void {
		$this->stored[Keys::responses(TrapUrl::ID)] = [ResponseType::Ban->value, ResponseType::ForcePasswordChange->value, 'nonsense'];
		$this->assertSame([ResponseType::Ban], $this->checks()->responses(TrapUrl::ID));
	}

	public function testRequirementsAndLearningModeComeFromTheStaticData(): void {
		$this->assertSame(ModeState::REASON_REQUIREMENT, $this->checks(false)->modeState(DirectoryScraping::ID)->reason);

		$this->stored[GlobalSettings::LEARNING_UNTIL] = 1_800_000_100;
		$this->assertSame(Mode::Observe, $this->checks()->effectiveMode(CredentialStuffing::ID));
	}

	public function testListItemsAreReadWithTheStaticRulesAndTheirUserSkipsTheUnusableOnes(): void {
		$this->stored[Keys::param(InjectionProbe::ID, InjectionProbe::PARAM_CUSTOM)] = ['union.*select', '(unclosed'];
		$this->assertSame(['union.*select', '(unclosed'], $this->checks()->paramList(InjectionProbe::ID, InjectionProbe::PARAM_CUSTOM));
	}

	public function testUnknownChecksThrow(): void {
		$this->expectException(InvalidParamException::class);
		$this->checks()->configuredMode('no_such_check');
	}

	public function testUnknownParametersThrow(): void {
		$this->expectException(InvalidParamException::class);
		$this->checks()->param(CredentialStuffing::ID, 'no_such_param');
	}

	public function testUnknownGlobalSettingsThrow(): void {
		$this->expectException(InvalidParamException::class);
		$this->app()->value('no_such_setting');
	}

	private function app(): AppSettings {
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturn(1_800_000_000);
		return new AppSettings($this->appConfig(), $time);
	}

	private function checks(bool $prerequisitesMet = true): CheckSettings {
		$prerequisites = $this->createMock(Prerequisites::class);
		$prerequisites->method('isMet')->willReturn($prerequisitesMet);
		return new CheckSettings($this->appConfig(), $this->app(), $prerequisites);
	}

	private function appConfig(): IAppConfig {
		$appConfig = $this->createMock(IAppConfig::class);
		foreach (['getValueInt', 'getValueFloat', 'getValueBool', 'getValueString', 'getValueArray'] as $method) {
			$appConfig->method($method)->willReturnCallback(fn (string $app, string $key, mixed $default): mixed => $this->stored[$key] ?? $default);
		}
		return $appConfig;
	}
}
