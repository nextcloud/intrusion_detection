<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Config;

use OCA\IntrusionDetection\Check\Checks\AdminChange\AdminChange;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffing\CredentialStuffing;
use OCA\IntrusionDetection\Config\AppSettings;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Keys;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Config\Prerequisites;
use OCA\IntrusionDetection\Definition\Mode;
use OCP\IAppConfig;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

/**
 * The mode a check ran in before one of the app's own settings changed, by
 * which a change that silences a check is still judged.
 */
class ModeBeforeTest extends TestCase {
	private const NOW = 1_800_000_000;

	/**
	 * The current state is the one after the change: configured mode, master switch, learning.
	 * Credential stuffing holds back while learning; the admin change check does not.
	 *
	 * @return array<string, array{0: string, 1: string, 2: int|float|bool|string|list<string>, 3: Mode, 4: bool, 5: bool, 6: Mode, 7: ?string}>
	 */
	public static function modesBefore(): array {
		$stuffing = CredentialStuffing::ID;
		$admin = AdminChange::ID;
		return [
			'switching the app off is told as before' => [$admin, GlobalSettings::ENABLED, true, Mode::Protect, false, false, Mode::Protect, null],
			'switching the app on was not watched' => [$admin, GlobalSettings::ENABLED, false, Mode::Protect, true, false, Mode::Off, ModeState::REASON_DISABLED],
			'the check to off is told as before' => [$admin, Keys::mode($admin), 'protect', Mode::Off, true, false, Mode::Protect, null],
			'the check from off was not watched' => [$admin, Keys::mode($admin), 'off', Mode::Protect, true, false, Mode::Off, null],
			'learning started is told as before' => [$stuffing, GlobalSettings::LEARNING_UNTIL, 0, Mode::Protect, true, true, Mode::Protect, null],
			'learning ended while learning' => [$stuffing, GlobalSettings::LEARNING_UNTIL, self::NOW + 60, Mode::Protect, true, false, Mode::Observe, ModeState::REASON_LEARNING],
			'learning does not silence a check that acts while learning' => [$admin, GlobalSettings::LEARNING_UNTIL, self::NOW + 60, Mode::Protect, true, false, Mode::Protect, null],
			'any setting while learning, acting while learning' => [$admin, GlobalSettings::BAN_NET_AFTER, 3, Mode::Protect, true, true, Mode::Protect, null],
			'any setting while learning' => [$stuffing, GlobalSettings::BAN_NET_AFTER, 3, Mode::Protect, true, true, Mode::Observe, ModeState::REASON_LEARNING],
			'any other setting' => [$stuffing, GlobalSettings::BAN_NET_AFTER, 3, Mode::Protect, true, false, Mode::Protect, null],
		];
	}

	/**
	 * @param int|float|bool|string|list<string> $old
	 */
	#[DataProvider('modesBefore')]
	public function testTheModeBeforeAChange(string $checkId, string $name, int|float|bool|string|array $old, Mode $configuredNow, bool $enabledNow, bool $learningNow, Mode $effective, ?string $reason): void {
		$appConfig = $this->createMock(IAppConfig::class);
		$appConfig->method('getValueString')->willReturn($configuredNow->value);
		$appSettings = $this->createMock(AppSettings::class);
		$appSettings->method('isEnabled')->willReturn($enabledNow);
		$appSettings->method('isLearning')->willReturn($learningNow);
		$prerequisites = $this->createMock(Prerequisites::class);
		$prerequisites->method('isMet')->willReturn(true);

		$mode = (new CheckSettings($appConfig, $appSettings, $prerequisites))->modeStateBefore($checkId, $name, $old, self::NOW);
		$this->assertSame($effective, $mode->effective);
		$this->assertSame($reason, $mode->reason);
	}
}
