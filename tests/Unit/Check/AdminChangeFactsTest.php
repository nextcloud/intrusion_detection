<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Check;

use OCA\IntrusionDetection\AdminChange\ActorResolver;
use OCA\IntrusionDetection\Check\Checks\AdminChange\AdminChange;
use OCA\IntrusionDetection\Check\Checks\AdminChange\AdminChangeDetector;
use OCA\IntrusionDetection\Check\Checks\AdminChange\AdminChangeFacts;
use OCA\IntrusionDetection\Notification\AdminAlerts;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

/**
 * The producers of an administration change hand its facts over as an
 * array; the facts class keeps every one of them.
 */
class AdminChangeFactsTest extends TestCase {
	/**
	 * @return array<string, array{array<string, mixed>}>
	 */
	public static function producedFacts(): array {
		return [
			'granted through a group' => [['group' => 'ids-team', 'delegated' => ['Users', 'Sharing'], 'exempt' => AdminChange::EXEMPT_OCC]],
			'granted after approval' => [['group' => 'admin', 'approval' => '7', 'requested_by' => 'carol', 'approved_by' => 'dave']],
			'held for approval' => [['group' => 'admin', 'reverted' => true, 'revert_failed' => false, 'approval' => '7', 'expires_at' => 1790000000]],
			'app switched on' => [['app' => 'files_external', 'groups' => ['staff']]],
			'setting' => [AdminChangeDetector::settingChange('system:trusted_proxies', null, ['10.0.0.1'], false, 'root', false, 1790000000)->facts],
			'secret setting' => [AdminChangeDetector::settingChange('system:secret', 'a', 'b', true, ActorResolver::UNKNOWN, true, 1790000000)->facts],
			'nothing' => [[]],
		];
	}

	/**
	 * @param array<string, mixed> $facts
	 */
	#[DataProvider('producedFacts')]
	public function testEveryProducedFactIsKept(array $facts): void {
		$kept = AdminChangeFacts::fromArray($facts)->toArray();
		ksort($facts);
		ksort($kept);
		$this->assertSame($facts, $kept);
	}

	public function testTheDetectionAddsTheChangeTheAccountAndTheAlert(): void {
		$facts = AdminChangeFacts::fromArray(['group' => 'admin'])->of(AdminChange::KIND_ADMIN_GRANTED, 'carol', 'alice', '192.0.2.4', 'admin_granted:admin');
		$this->assertSame(AdminChange::KIND_ADMIN_GRANTED, $facts->kind);
		$this->assertSame('carol', $facts->actor);
		$this->assertSame(['alice'], $facts->common->targets);
		$this->assertSame('192.0.2.4', $facts->actorIp);
		$this->assertSame('admin', $facts->group);
		$this->assertSame('admin_granted:admin', $facts->toArray()[AdminAlerts::FACT_ALERT_KEY]);
		$this->assertTrue($facts->toArray()[AdminAlerts::FACT_ALL_ADMINS]);
		$this->assertArrayNotHasKey('targets', AdminChangeFacts::fromArray([])->of(AdminChange::KIND_APP_ENABLED, 'root', null, null, 'app_enabled')->toArray());
	}
}
