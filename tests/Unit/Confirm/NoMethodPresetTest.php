<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Confirm;

use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Configure\SettingsEditor;
use OCA\IntrusionDetection\Confirm\NoMethodOutcome;
use OCA\IntrusionDetection\Confirm\NoMethodPreset;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Definition\InvalidParamException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;

/**
 * The one choice for logins that nothing can confirm: every reason is
 * written at once, and a mix set per reason is "custom".
 */
class NoMethodPresetTest extends TestCase {
	private AppSettings&MockObject $settings;
	private SettingsEditor&MockObject $editor;

	protected function setUp(): void {
		parent::setUp();
		$this->settings = $this->createMock(AppSettings::class);
		$this->editor = $this->createMock(SettingsEditor::class);
	}

	/**
	 * @return list<string>
	 */
	private static function keys(): array {
		return array_map(static fn (StepUpPolicy $p): string => $p->settingKey(), StepUpPolicy::cases());
	}

	public function testRecommendedIsTheDefaultOfEachReason(): void {
		$outcomes = NoMethodPreset::outcomes(NoMethodPreset::RECOMMENDED);
		$this->assertSame(self::keys(), array_keys($outcomes));
		foreach (StepUpPolicy::cases() as $policy) {
			$this->assertSame($policy->defaultOutcome()->value, $outcomes[$policy->settingKey()], $policy->value);
		}
	}

	public function testRefuseRefusesEveryReason(): void {
		$outcomes = NoMethodPreset::outcomes(NoMethodPreset::REFUSE);
		$this->assertSame(self::keys(), array_keys($outcomes));
		$this->assertSame([NoMethodOutcome::Refuse->value], array_values(array_unique($outcomes)));
	}

	public function testAllowLetsEveryLoginInAndALeakedPasswordMustChange(): void {
		$outcomes = NoMethodPreset::outcomes(NoMethodPreset::ALLOW);
		$this->assertSame(self::keys(), array_keys($outcomes));
		foreach (StepUpPolicy::cases() as $policy) {
			$expected = $policy === StepUpPolicy::BreachedPassword ? NoMethodOutcome::AllowForceChange : NoMethodOutcome::AllowNotify;
			$this->assertSame($expected->value, $outcomes[$policy->settingKey()], $policy->value);
		}
	}

	/**
	 * @return array<string, array{string}>
	 */
	public static function unknown(): array {
		return ['custom' => ['custom'], 'empty' => [''], 'an outcome' => ['allow_notify']];
	}

	#[DataProvider('unknown')]
	public function testOnlyThePresetsCanBeSet(string $preset): void {
		$this->editor->expects($this->never())->method('updateGlobals');
		$this->expectException(InvalidParamException::class);
		(new NoMethodPreset($this->settings, $this->editor))->apply($preset);
	}

	public function testApplyWritesEveryReasonInOneValidatedCall(): void {
		$this->editor->expects($this->once())->method('updateGlobals')
			->with(NoMethodPreset::outcomes(NoMethodPreset::REFUSE))
			->willReturn(['step_up_no_method_protected_account' => 'refuse']);
		$this->assertSame(['step_up_no_method_protected_account' => 'refuse'], (new NoMethodPreset($this->settings, $this->editor))->apply(NoMethodPreset::REFUSE));
	}

	/**
	 * @return array<string, array{string}>
	 */
	public static function presets(): array {
		return array_combine(NoMethodPreset::PRESETS, array_map(static fn (string $p): array => [$p], NoMethodPreset::PRESETS));
	}

	#[DataProvider('presets')]
	public function testTheStoredOutcomesNameTheirPreset(string $preset): void {
		$stored = NoMethodPreset::outcomes($preset);
		$this->settings->method('stepUpNoMethod')->willReturnCallback(static fn (string $policy): string => $stored['step_up_no_method_' . $policy]);
		$this->assertSame($preset, (new NoMethodPreset($this->settings, $this->editor))->current());
	}

	public function testAMixSetPerReasonIsCustom(): void {
		$stored = NoMethodPreset::outcomes(NoMethodPreset::REFUSE);
		$stored[StepUpPolicy::RiskyNetwork->settingKey()] = NoMethodOutcome::AllowNotify->value;
		$this->settings->method('stepUpNoMethod')->willReturnCallback(static fn (string $policy): string => $stored['step_up_no_method_' . $policy]);
		$this->assertSame(NoMethodPreset::CUSTOM, (new NoMethodPreset($this->settings, $this->editor))->current());
	}
}
