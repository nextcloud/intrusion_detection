<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Admin;

use OCA\IntrusionDetection\Admin\CheckList;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Config\Prerequisites;
use OCA\IntrusionDetection\Db\StatsMapper;
use OCA\IntrusionDetection\Definition\Category;
use OCA\IntrusionDetection\Definition\CheckDefinition;
use OCA\IntrusionDetection\Definition\CheckTexts;
use OCA\IntrusionDetection\Definition\CostClass;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\ParamDefinition;
use OCA\IntrusionDetection\Definition\ParamText;
use OCA\IntrusionDetection\Definition\ParamType;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Definition\Severity;
use OCA\IntrusionDetection\Detection\DetectionTotals;
use OCA\IntrusionDetection\Explain\CheckPresenter;
use OCA\IntrusionDetection\Explain\TextRenderer;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IL10N;
use OCP\L10N\IFactory;
use OCP\Server;
use Test\TestCase;

/**
 * The Protection tab renders whatever the registry holds, grouped by category,
 * with the texts filled in and the counts of the last 7 days.
 */
class CheckListTest extends TestCase {
	public function testChecksAreGroupedPresentedAndCounted(): void {
		$traps = self::definition('trap_check', Category::Traps);
		$login = self::definition('login_check', Category::LoginAttacks);
		$registry = $this->createMock(CheckRegistry::class);
		$registry->method('configurable')->willReturn(['trap_check' => $traps, 'login_check' => $login]);

		$settings = $this->createMock(CheckSettings::class);
		$settings->method('placeholderValues')->willReturn(['min_failures' => 12, 'window' => 900, 'ban_duration_1' => 14400]);
		$settings->method('modeState')->willReturn(new ModeState(Mode::Protect, Mode::Observe, ModeState::REASON_LEARNING));
		$settings->method('responses')->willReturn([ResponseType::NotifyAdmin, ResponseType::Ban]);
		$settings->method('param')->willReturnCallback(static fn (string $check, string $name): int => ['min_failures' => 12, 'window' => 900][$name]);

		$totals = $this->createMock(DetectionTotals::class);
		$totals->expects($this->once())->method('perCheck')->with(1_790_000_000 - 7 * 86400)->willReturn(['login_check' => ['enforced' => 2, 'observed' => 1]]);
		$stats = $this->createMock(StatsMapper::class);
		$stats->method('bansCreatedByCheck')->willReturn(['login_check' => 9]);
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturn(1_790_000_000);

		$list = new CheckList(
			$registry,
			new CheckPresenter($settings, $this->createMock(Prerequisites::class), new TextRenderer(new GlobalSettings())),
			$totals,
			$stats,
			$time,
		);
		$result = $list->all(Server::get(IFactory::class)->get('intrusion_detection', 'en'));

		// Categories in their own order, only those with checks.
		$this->assertSame(['login_attacks', 'traps'], array_column($result['categories'], 'id'));
		$this->assertSame('Login attacks', $result['categories'][0]['name']);

		$login = $result['checks'][1];
		$this->assertSame(['days' => 7, 'detections' => 3, 'enforced' => 2, 'observed' => 1, 'addressesBlocked' => 9], $login['stats']);
		$this->assertSame(0, $result['checks'][0]['stats']['detections']);
		$this->assertSame('Fires at 12 failures within 15 minutes.', $login['decides']);
		$this->assertSame('Fires at {min_failures} failures within {window}.', $login['decidesTemplate']);
		$this->assertSame(['configured' => 'protect', 'effective' => 'observe', 'reason' => 'learning', 'missing' => null, 'default' => 'protect'], $login['mode']);

		// Responses run blocks first; "what happens" fills in the durations.
		$this->assertSame('The address is blocked for 4 hours ({ban_duration_2} if it is blocked again within {ban_history_days} days, then {ban_duration_3}).', $login['happens'][0]);
		$this->assertSame('Notify the administrators.', $login['happens'][1]);
		$this->assertSame(10, $login['responses'][0]['order']);
		$this->assertStringContainsString('{ban_duration_1}', $login['responses'][0]['happens']);

		// Parameters carry their texts, or a readable fallback.
		$this->assertSame(['Failed logins', 'Counted when a login fails.', 'failures'], [$login['params'][0]['label'], $login['params'][0]['help'], $login['params'][0]['unit']]);
		$this->assertSame('Window', $login['params'][1]['label']);
		$this->assertSame(900, $login['params'][1]['value']);
	}

	private static function definition(string $id, Category $category): CheckDefinition {
		return new CheckDefinition(
			id: $id,
			category: $category,
			defaultMode: Mode::Protect,
			severity: Severity::Medium,
			params: [
				new ParamDefinition('min_failures', ParamType::Int, 10, min: 3, max: 1000),
				new ParamDefinition('window', ParamType::Duration, 600, min: 60, max: 3600),
			],
			responses: [ResponseType::Ban, ResponseType::NotifyAdmin],
			defaultResponses: [ResponseType::Ban],
			cost: CostClass::OnFailureOnly,
			stores: [],
			texts: static fn (IL10N $l): CheckTexts => new CheckTexts(
				'Name', 'Summary', 'Detects', 'Fires at {min_failures} failures within {window}.', 'Wrong', 'Data',
				params: ['min_failures' => new ParamText('Failed logins', 'Counted when a login fails.', 'failures')],
			),
		);
	}
}
