<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Check\Payload;

use OCA\IntrusionDetection\Check\Checks\InjectionProbe;
use OCA\IntrusionDetection\Check\Payload\PayloadSettings;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Definition\Mode;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

class PayloadSettingsTest extends TestCase {
	/**
	 * @return array<string, array{ModeState, string, Mode, ?string}>
	 */
	public static function modes(): array {
		return [
			'observe by default' => [new ModeState(Mode::Protect, Mode::Protect), 'observe', Mode::Observe, ModeState::REASON_AUTHENTICATED],
			'protect when chosen' => [new ModeState(Mode::Protect, Mode::Protect), 'protect', Mode::Protect, null],
			'off when chosen' => [new ModeState(Mode::Protect, Mode::Protect), 'off', Mode::Off, null],
			'learning mode observes' => [new ModeState(Mode::Protect, Mode::Observe, ModeState::REASON_LEARNING), 'protect', Mode::Observe, ModeState::REASON_LEARNING],
			'the check in Observe is the ceiling' => [new ModeState(Mode::Observe, Mode::Observe), 'protect', Mode::Observe, null],
			'the check off turns it off' => [new ModeState(Mode::Off, Mode::Off), 'protect', Mode::Off, null],
			'the master switch turns it off' => [new ModeState(Mode::Protect, Mode::Off, ModeState::REASON_DISABLED), 'observe', Mode::Off, ModeState::REASON_DISABLED],
			'an unknown stored value observes' => [new ModeState(Mode::Protect, Mode::Protect), 'nonsense', Mode::Observe, ModeState::REASON_AUTHENTICATED],
		];
	}

	#[DataProvider('modes')]
	public function testAuthenticatedMode(ModeState $check, string $chosen, Mode $effective, ?string $reason): void {
		$settings = $this->createMock(CheckSettings::class);
		$settings->method('modeState')->with(InjectionProbe::ID)->willReturn($check);
		$settings->method('param')->with(InjectionProbe::ID, InjectionProbe::PARAM_AUTHENTICATED_MODE)->willReturn($chosen);
		$state = (new PayloadSettings($settings))->authenticatedMode();
		$this->assertSame($effective, $state->effective);
		$this->assertSame($reason, $state->reason);
	}

	public function testRulesComeFromTheSettings(): void {
		$settings = $this->createMock(CheckSettings::class);
		$settings->method('paramInt')->willReturnMap([
			[InjectionProbe::ID, InjectionProbe::PARAM_MIN_WEIGHT, 4],
			[InjectionProbe::ID, InjectionProbe::PARAM_MAX_BYTES, 2048],
		]);
		$settings->method('paramList')->willReturnMap([
			[InjectionProbe::ID, InjectionProbe::PARAM_DISABLED, ['sql_sleep']],
			[InjectionProbe::ID, InjectionProbe::PARAM_CUSTOM, ['2:foo\d']],
			[InjectionProbe::ID, InjectionProbe::PARAM_EXCLUDED, ['Legacy']],
		]);
		$rules = (new PayloadSettings($settings))->rules();
		$this->assertSame(4, $rules->minWeight);
		$this->assertSame(2048, $rules->maxBytes);
		$ids = array_map(static fn ($s): string => $s->id, $rules->signatures);
		$this->assertNotContains('sql_sleep', $ids);
		$this->assertContains('sql_union_select', $ids);
		$signatures = $rules->signatures;
		$this->assertSame(2, end($signatures)->weight);
		$this->assertSame('free_text', $rules->exclusion('legacy', false), 'Names are compared case-insensitively');
	}
}
