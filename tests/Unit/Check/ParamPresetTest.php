<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Check;

use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Definition\ParamDefinition;
use OCA\IntrusionDetection\Definition\ParamPreset;
use OCA\IntrusionDetection\Definition\ParamType;
use OCA\IntrusionDetection\Definition\ProtectionLevel;
use OCP\Server;
use Test\TestCase;

/**
 * The protection levels change the count limits and block durations from
 * their defaults, never outside a parameter's range.
 */
class ParamPresetTest extends TestCase {
	public function testStrictHalvesLimitsAndRelaxedDoublesThem(): void {
		$limit = new ParamDefinition('min_failures', ParamType::Int, 10, min: 3, max: 1000, preset: ParamPreset::Limit);
		$this->assertSame(10, $limit->presetValue(ProtectionLevel::Recommended));
		$this->assertSame(5, $limit->presetValue(ProtectionLevel::Strict));
		$this->assertSame(20, $limit->presetValue(ProtectionLevel::Relaxed));
	}

	public function testStrictLengthensBlocksAndRelaxedShortensThem(): void {
		$duration = new ParamDefinition('ban_duration_1', ParamType::Duration, 14400, min: 300, max: 7776000, preset: ParamPreset::BlockDuration);
		$this->assertSame(28800, $duration->presetValue(ProtectionLevel::Strict));
		$this->assertSame(7200, $duration->presetValue(ProtectionLevel::Relaxed));
	}

	public function testValuesStayWithinTheRange(): void {
		$low = new ParamDefinition('min_names', ParamType::Int, 5, min: 3, max: 8, preset: ParamPreset::Limit);
		$this->assertSame(3, $low->presetValue(ProtectionLevel::Strict), 'half of 5 rounds to 3, the minimum');
		$this->assertSame(8, $low->presetValue(ProtectionLevel::Relaxed), 'twice 5 is above the maximum of 8');

		$tiny = new ParamDefinition('ban_min_failures', ParamType::Int, 1, min: 1, max: 100, preset: ParamPreset::Limit);
		$this->assertSame(1, $tiny->presetValue(ProtectionLevel::Strict), 'a limit never drops below 1');

		$long = new ParamDefinition('ban_duration_3', ParamType::Duration, 60 * 86400, min: 300, max: 90 * 86400, preset: ParamPreset::BlockDuration);
		$this->assertSame(90 * 86400, $long->presetValue(ProtectionLevel::Strict));
	}

	public function testParametersWithoutAPresetAndCustomAreLeftAlone(): void {
		$window = new ParamDefinition('window', ParamType::Duration, 600, min: 60, max: 3600);
		$this->assertNull($window->presetValue(ProtectionLevel::Strict));
		$limit = new ParamDefinition('min_failures', ParamType::Int, 10, preset: ParamPreset::Limit);
		$this->assertNull($limit->presetValue(ProtectionLevel::Custom));
	}

	public function testOnlyWholeNumbersCanHaveAPreset(): void {
		$this->expectException(\InvalidArgumentException::class);
		new ParamDefinition('ratio', ParamType::Float, 1.5, preset: ParamPreset::Limit);
	}

	public function testEveryPresetDefaultIsValidAtEveryLevel(): void {
		$definitions = [];
		foreach (Server::get(CheckRegistry::class)->all() as $check) {
			foreach ($check->params as $param) {
				$definitions[$check->id . '.' . $param->name] = $param;
			}
		}
		foreach ((new GlobalSettings())->all() as $name => $param) {
			$definitions[$name] = $param;
		}
		$withPreset = 0;
		foreach ($definitions as $key => $param) {
			foreach (ProtectionLevel::choosable() as $level) {
				$value = $param->presetValue($level);
				if ($value !== null) {
					$this->assertSame($value, $param->validate($value), $key . ' at ' . $level->value);
				}
			}
			$withPreset += $param->preset === null ? 0 : 1;
		}
		$this->assertGreaterThan(20, $withPreset);
		$this->assertSame(ParamPreset::BlockDuration, (new GlobalSettings())->get(GlobalSettings::BAN_DURATION_2)?->preset);
		$this->assertNull((new GlobalSettings())->get(GlobalSettings::BAN_HISTORY_DAYS)?->preset, 'only the counts and block durations change');
	}
}
