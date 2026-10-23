<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Incident\DataCategory;
use OCA\IntrusionDetection\Incident\IncidentQuery;
use OCA\IntrusionDetection\Incident\IncidentReportBuilder;
use OCA\IntrusionDetection\Incident\Sources\SecurityChangeSource;
use OCA\IntrusionDetection\Incident\TimelineEntry;
use OCA\IntrusionDetection\Takeover\Db\SecurityChangeMapper;
use OCA\IntrusionDetection\Takeover\SecurityChangeLog;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * The incident report's timeline source for security changes, revoked app
 * passwords included (concept section 16.6).
 */
#[Group('DB')]
class SecurityChangeSourceTest extends IntegrationTestCase {
	public function testItIsPartOfEveryReport(): void {
		$this->assertContains(SecurityChangeSource::class, IncidentReportBuilder::SOURCES);
	}

	public function testAnAccountsChangesInThePeriod(): void {
		$now = time();
		$this->change('ids-src-alice', 'email_changed', SecurityChangeLog::VIA_SELF, $now - 300, ['old_value_hint' => 'a***@example.com', 'new_value_hint' => 'e***@evil.example', 'notify_to' => 'encrypted-address']);
		$this->change('ids-src-alice', 'app_password_created', SecurityChangeLog::VIA_SELF, $now - 200, ['detail' => 'Attacker sync']);
		$this->change('ids-src-alice', 'app_password_revoked', SecurityChangeLog::VIA_ADMIN, $now - 100, ['detail' => 'Attacker sync', 'actor_uid' => 'admin']);
		$this->change('ids-src-alice', 'password_changed', SecurityChangeLog::VIA_SELF, $now - 30 * 86400);
		$this->change('ids-src-bob', 'password_changed', SecurityChangeLog::VIA_SELF, $now - 100);

		$entries = $this->entries(IncidentQuery::forUser('ids-src-alice', null, null, $now + 1));
		$this->assertSame(['Email address changed', 'App password created', 'App password revoked'], array_map(static fn (TimelineEntry $e): string => $e->title, $entries));
		$this->assertSame('security_change', $entries[0]->kind);
		$this->assertContains('Previous address: a***@example.com. New address: e***@evil.example.', $entries[0]->details);
		$this->assertContains('From the address 203.0.113.7.', $entries[0]->details);
		$this->assertSame([DataCategory::AccountContent], $entries[0]->categories);
		$this->assertNotNull($entries[0]->followUp);
		$this->assertSame([DataCategory::ConnectedDevices], $entries[1]->categories);
		$this->assertContains('Made by the administrator admin.', $entries[2]->details);
		$this->assertSame([], $entries[2]->categories, 'Changes by others say nothing about a stolen account');
		$this->assertSame(['An app password of ids-src-alice was revoked: "Attacker sync".'], $entries[2]->measures);
		$this->assertStringNotContainsString('encrypted-address', json_encode(array_map(static fn (TimelineEntry $e): array => $e->toArray(), $entries), JSON_THROW_ON_ERROR));
	}

	public function testAnAddressesChanges(): void {
		$now = time();
		$this->change('ids-src-alice', 'password_changed', SecurityChangeLog::VIA_SELF, $now - 100);
		$this->change('ids-src-bob', 'password_changed', SecurityChangeLog::VIA_SELF, $now - 50, ['ip' => '198.51.100.1']);
		$entries = $this->entries(IncidentQuery::forAddress('203.0.113.7', null, null, $now + 1));
		$this->assertCount(1, $entries);
		$this->assertSame('Password changed: ids-src-alice', $entries[0]->title);
		$this->assertSame(['ids-src-alice'], $entries[0]->accounts);
	}

	/**
	 * @return list<TimelineEntry>
	 */
	private function entries(IncidentQuery $query): array {
		$source = Server::get(SecurityChangeSource::class);
		return iterator_to_array($source->entriesFor($query, Server::get(IFactory::class)->get(Application::APP_ID, 'en')), false);
	}

	/**
	 * @param array<string, mixed> $values
	 */
	private function change(string $uid, string $type, string $via, int $at, array $values = []): void {
		Server::get(SecurityChangeMapper::class)->insert(array_merge([
			'uid' => $uid, 'type' => $type, 'via' => $via, 'actor_uid' => $via === SecurityChangeLog::VIA_SELF ? $uid : null,
			'old_value_hint' => null, 'new_value_hint' => null, 'notify_to' => null, 'ref_id' => null, 'detail' => null,
			'session_token_id' => null, 'ip' => '203.0.113.7', 'created_at' => $at,
		], $values));
	}
}
