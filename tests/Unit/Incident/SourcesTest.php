<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Incident;

use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Incident\DataCategory;
use OCA\IntrusionDetection\Incident\IncidentQuery;
use OCA\IntrusionDetection\Incident\ReportNote;
use OCA\IntrusionDetection\Incident\Sources\ActivitySource;
use OCA\IntrusionDetection\Incident\Sources\ShareSource;
use OCA\IntrusionDetection\Incident\TimelineEntry;
use OCP\App\IAppManager;
use OCP\Constants;
use OCP\IL10N;
use OCP\IURLGenerator;
use OCP\L10N\IFactory;
use OCP\Server;
use OCP\Share\IManager;
use OCP\Share\IShare;
use Psr\Log\LoggerInterface;
use Test\TestCase;

/**
 * The share and activity sources, which read from core rather than from
 * the app's own tables.
 */
class SourcesTest extends TestCase {
	private const NOW = 1_800_000_000;

	private IL10N $l;

	protected function setUp(): void {
		parent::setUp();
		$this->l = Server::get(IFactory::class)->get('intrusion_detection', 'en');
	}

	private function share(int $id, int $type, int $createdAt, ?string $with = null): IShare {
		$share = $this->createMock(IShare::class);
		$share->method('getFullId')->willReturn('ocinternal:' . $id);
		$share->method('getShareType')->willReturn($type);
		$share->method('getTarget')->willReturn('/Projects/plan-' . $id . '.md');
		$share->method('getSharedWith')->willReturn($with);
		$share->method('getShareTime')->willReturn(new \DateTime('@' . $createdAt));
		$share->method('getNodeType')->willReturn('folder');
		$share->method('getPermissions')->willReturn(Constants::PERMISSION_READ);
		$share->method('getPassword')->willReturn(null);
		$share->method('getExpirationDate')->willReturn(new \DateTime('@' . (self::NOW + 86400)));
		$share->expects($this->never())->method('getToken');
		return $share;
	}

	private function shares(IManager $manager): ShareSource {
		$dates = $this->createMock(DateFormatter::class);
		$dates->method('dateTime')->willReturnCallback(static fn (int $t): string => '@' . $t);
		return new ShareSource($manager, $dates, $this->createMock(LoggerInterface::class));
	}

	public function testSharesOfThePeriodOldestFirstWithoutTheirToken(): void {
		$manager = $this->createMock(IManager::class);
		$manager->method('getSharesBy')->willReturnCallback(fn (string $uid, int $type): array => match ($type) {
			IShare::TYPE_LINK => [$this->share(3, IShare::TYPE_LINK, self::NOW - 100), $this->share(1, IShare::TYPE_LINK, self::NOW - 30 * 86400)],
			IShare::TYPE_ROOM => [$this->share(4, IShare::TYPE_ROOM, self::NOW - 200, 'roomtokenxyz')],
			IShare::TYPE_GROUP => [$this->share(2, IShare::TYPE_GROUP, self::NOW - 300, 'staff')],
			default => [],
		});
		$query = IncidentQuery::forUser('alice', null, null, self::NOW)->withLimit(10);
		$entries = iterator_to_array($this->shares($manager)->entriesFor($query, $this->l), false);

		$this->assertSame(['share:ocinternal:2', 'share:ocinternal:4', 'share:ocinternal:3'], array_map(static fn (TimelineEntry $e): string => $e->id, $entries));
		$this->assertSame('"plan-2.md" shared with the group staff', $entries[0]->title);
		$this->assertSame('"plan-4.md" shared in a conversation', $entries[1]->title, 'the conversation token is not a recipient to show');
		$this->assertStringNotContainsString('roomtokenxyz', json_encode(array_map(static fn (TimelineEntry $e): array => $e->toArray(), $entries), JSON_THROW_ON_ERROR));
		$this->assertSame('Public link to "plan-3.md" created', $entries[2]->title);
		$this->assertSame(['A folder.', 'It has no password.', 'Expiry date: @' . (self::NOW + 86400) . '.'], $entries[2]->details);
		$this->assertSame([DataCategory::SharedFiles], $entries[2]->categories);
		$this->assertSame([], $this->shares($manager)->notesFor($query, $this->l));
	}

	public function testAnAddressHasNoShares(): void {
		$manager = $this->createMock(IManager::class);
		$manager->expects($this->never())->method('getSharesBy');
		$this->assertSame([], iterator_to_array($this->shares($manager)->entriesFor(IncidentQuery::forAddress('198.51.100.7', null, null, self::NOW), $this->l), false));
	}

	public function testTooManySharesAreLookedAtOnlyUpToTheLimitAndTheReportSaysSo(): void {
		$page = [];
		for ($i = 0; $i < 500; $i++) {
			$page[] = $this->share($i, IShare::TYPE_LINK, self::NOW - 60 * 86400);
		}
		$calls = 0;
		$manager = $this->createMock(IManager::class);
		$manager->method('getSharesBy')->willReturnCallback(function (string $uid, int $type, $path, bool $reshares, int $limit, int $offset, bool $onlyValid) use ($page, &$calls): array {
			$this->assertFalse($onlyValid, 'expired shares count, and nothing is cleaned up on the way');
			$this->assertFalse($reshares);
			if ($type !== IShare::TYPE_LINK) {
				return [];
			}
			$calls++;
			return $page;
		});
		$source = $this->shares($manager);
		$query = IncidentQuery::forUser('alice', null, null, self::NOW)->withLimit(10);
		$this->assertSame([], iterator_to_array($source->entriesFor($query, $this->l), false));
		$this->assertSame(ShareSource::SCAN_LIMIT / 500, $calls);
		$notes = $source->notesFor($query, $this->l);
		$this->assertCount(1, $notes);
		$this->assertSame('shares_incomplete', $notes[0]->id);
		$this->assertSame([], $source->notesFor(IncidentQuery::forUser('alice', null, null, self::NOW), $this->l), 'only for the query that hit the limit');
	}

	public function testFileActionsPointToTheActivityStreamAndTheAuditLog(): void {
		$urls = $this->createMock(IURLGenerator::class);
		$urls->method('getAbsoluteURL')->willReturnCallback(static fn (string $p): string => 'https://cloud.example.org' . $p);
		$apps = $this->createMock(IAppManager::class);
		$apps->method('isEnabledForAnyone')->willReturnMap([['activity', true], ['admin_audit', true]]);
		$source = new ActivitySource($apps, $urls);
		$user = IncidentQuery::forUser('alice', null, null, self::NOW);

		$this->assertSame([], $source->kinds($this->l));
		$this->assertSame([], $source->entriesFor($user, $this->l));
		$notes = $source->notesFor($user, $this->l);
		$this->assertSame(['file_actions', 'audit_log'], array_map(static fn (ReportNote $n): string => $n->id, $notes));
		$this->assertSame('https://cloud.example.org/index.php/apps/activity/', $notes[0]->url);

		$apps = $this->createMock(IAppManager::class);
		$apps->method('isEnabledForAnyone')->willReturn(false);
		$notes = (new ActivitySource($apps, $urls))->notesFor($user, $this->l);
		$this->assertCount(1, $notes);
		$this->assertNull($notes[0]->url);
		$this->assertStringContainsString('not enabled', $notes[0]->text);

		$address = (new ActivitySource($apps, $urls))->notesFor(IncidentQuery::forAddress('198.51.100.7', null, null, self::NOW), $this->l);
		$this->assertStringContainsString('per account, not per address', $address[0]->text);
	}
}
