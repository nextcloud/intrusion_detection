<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Incident;

use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Incident\DataCategory;
use OCA\IntrusionDetection\Incident\IAddsReportNotes;
use OCA\IntrusionDetection\Incident\IncidentQuery;
use OCA\IntrusionDetection\Incident\IncidentReport;
use OCA\IntrusionDetection\Incident\IncidentReportBuilder;
use OCA\IntrusionDetection\Incident\ITimelineSource;
use OCA\IntrusionDetection\Incident\ReportNote;
use OCA\IntrusionDetection\Incident\TimelineEntry;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IL10N;
use OCP\IURLGenerator;
use OCP\IUser;
use OCP\IUserManager;
use OCP\L10N\IFactory;
use OCP\Server;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Test\TestCase;

/**
 * The merge, the cap and the summary, with fake sources in place of the
 * real ones.
 */
class IncidentReportBuilderTest extends TestCase {
	private const NOW = 1_800_000_000;

	private IL10N $l;
	/** @var list<int> limits the sources were asked with */
	private array $limits = [];

	protected function setUp(): void {
		parent::setUp();
		$this->l = Server::get(IFactory::class)->get('intrusion_detection', 'en');
	}

	/**
	 * @param array<int, ITimelineSource> $sources by position in SOURCES; missing ones return nothing
	 */
	private function builder(array $sources, int $maxEntries = IncidentReportBuilder::MAX_ENTRIES, ?LoggerInterface $logger = null): IncidentReportBuilder {
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willReturnCallback(function (string $class) use ($sources): ITimelineSource {
			$index = array_search($class, IncidentReportBuilder::SOURCES, true);
			return $sources[$index] ?? $this->source('none' . $index, []);
		});
		$alice = $this->createMock(IUser::class);
		$alice->method('getDisplayName')->willReturn('Alice Liddell');
		$users = $this->createMock(IUserManager::class);
		$users->method('get')->willReturnCallback(static fn (string $uid): ?IUser => $uid === 'alice' ? $alice : null);
		$urls = $this->createMock(IURLGenerator::class);
		$urls->method('getBaseUrl')->willReturn('https://cloud.example.org');
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturn(self::NOW);
		$dates = $this->createMock(DateFormatter::class);
		$dates->method('dateTime')->willReturnCallback(static fn (int $t): string => '@' . $t);
		return new IncidentReportBuilder($container, $users, $urls, $time, $dates, $logger ?? $this->createMock(LoggerInterface::class), $maxEntries);
	}

	/**
	 * @param list<TimelineEntry> $entries
	 * @param list<ReportNote> $notes
	 */
	private function source(string $kind, array $entries, array $notes = [], ?\Throwable $fails = null): ITimelineSource {
		$limits = &$this->limits;
		return new class($kind, $entries, $notes, $fails, $limits) implements ITimelineSource, IAddsReportNotes {
			/**
			 * @param list<TimelineEntry> $entries
			 * @param list<ReportNote> $notes
			 * @param list<int> $limits
			 */
			public function __construct(
				private string $kind,
				private array $entries,
				private array $notes,
				private ?\Throwable $fails,
				private array &$limits,
			) {
			}

			public function kinds(IL10N $l): array {
				return [$this->kind => ucfirst($this->kind)];
			}

			public function entriesFor(IncidentQuery $query, IL10N $l): iterable {
				$this->limits[] = $query->limit;
				if ($this->fails !== null) {
					throw $this->fails;
				}
				yield from array_slice($this->entries, 0, $query->limit);
			}

			public function notesFor(IncidentQuery $query, IL10N $l): array {
				return $this->notes;
			}
		};
	}

	/**
	 * @param list<DataCategory> $categories
	 * @param list<string> $done
	 */
	private static function entry(string $id, int $at, string $kind = 'detection', ?string $severity = null, ?bool $enforced = null, array $done = [], array $categories = [], ?string $followUp = null, ?string $address = null, array $accounts = [], string $group = 'Group'): TimelineEntry {
		return new TimelineEntry($id, $at, $kind, $group, 'Title ' . $id, severity: $severity, enforced: $enforced, done: $done, address: $address, accounts: $accounts, categories: $categories, followUp: $followUp);
	}

	private function user(): IncidentQuery {
		return IncidentQuery::forUser('alice', self::NOW - 86400, self::NOW, self::NOW);
	}

	public function testEntriesAreMergedByTimeAndBySourceWithinTheSameSecond(): void {
		$report = $this->builder([
			0 => $this->source('detection', [self::entry('d1', 100), self::entry('d2', 300)]),
			1 => $this->source('block', [self::entry('b1', 100, 'block'), self::entry('b2', 200, 'block')]),
			4 => $this->source('share', [self::entry('s1', 50, 'share')]),
		])->build($this->user(), 'admin', $this->l);

		$this->assertSame(['s1', 'd1', 'b1', 'b2', 'd2'], array_map(static fn (TimelineEntry $e): string => $e->id, $report->entries));
		$this->assertFalse($report->truncated);
		$this->assertSame(IncidentReportBuilder::MAX_ENTRIES + 1, $this->limits[0], 'sources are asked for one more than fits');
		$kinds = array_column($report->kinds, 'count', 'id');
		$this->assertSame(2, $kinds['detection']);
		$this->assertSame(2, $kinds['block']);
		$this->assertSame(1, $kinds['share']);
		$this->assertSame(0, $kinds['none2'], 'kinds without entries are listed for the filters');
	}

	public function testTheCapKeepsTheOldestEntriesAndSaysTruncated(): void {
		$report = $this->builder([
			0 => $this->source('detection', [self::entry('d1', 10), self::entry('d2', 20), self::entry('d3', 30), self::entry('d4', 40), self::entry('d5', 50)]),
			1 => $this->source('block', [self::entry('b1', 15, 'block'), self::entry('b2', 60, 'block')]),
		], 3)->build($this->user(), 'admin', $this->l);

		$this->assertTrue($report->truncated);
		$this->assertSame(3, $report->maxEntries);
		$this->assertSame(['d1', 'b1', 'd2'], array_map(static fn (TimelineEntry $e): string => $e->id, $report->entries));
		$this->assertSame(4, $this->limits[0]);
		$this->assertStringContainsString('incomplete', implode(' ', $report->summary->openItems));
		$this->assertTrue($report->toArray()['truncated']);
	}

	public function testExactlyAtTheCapIsComplete(): void {
		$report = $this->builder([0 => $this->source('detection', [self::entry('d1', 10), self::entry('d2', 20)])], 2)->build($this->user(), 'admin', $this->l);
		$this->assertFalse($report->truncated);
		$this->assertCount(2, $report->entries);
	}

	public function testASourceThatFailsIsNamedAndTheOthersStillCount(): void {
		$logger = $this->createMock(LoggerInterface::class);
		$logger->expects($this->once())->method('error');
		$report = $this->builder([
			0 => $this->source('detection', [self::entry('d1', 10)]),
			2 => $this->source('app_password', [], [], new \RuntimeException('database gone')),
			5 => $this->source('activity', [], [new ReportNote('file_actions', 'Look in the activity stream.')]),
		], logger: $logger)->build($this->user(), 'admin', $this->l);

		$this->assertCount(1, $report->entries);
		$notes = array_map(static fn (ReportNote $n): string => $n->id . ': ' . $n->text, $report->notes);
		$this->assertContains('file_actions: Look in the activity stream.', $notes);
		$this->assertStringContainsString('(App_password)', implode("\n", $notes));
	}

	public function testTheLastActivityIsWhenSomethingWasLastSeenNotWhenABlockEnds(): void {
		$report = $this->builder([
			0 => $this->source('detection', [new TimelineEntry('d1', 100, 'detection', 'Group', 'Title d1', lastSeenAt: 250)]),
			1 => $this->source('block', [new TimelineEntry('b1', 200, 'block', 'Blocks', 'Title b1', endsAt: self::NOW + 4 * 3600, ref: ['type' => 'block', 'id' => '2S8X-AXQ6'])]),
		])->build($this->user(), 'admin', $this->l);

		$this->assertSame(250, $report->summary->lastActivityAt);
	}

	public function testOnlyTheReferencesOfBlocksAreQuoted(): void {
		$block = new TimelineEntry('b1', 200, 'block', 'Blocks', 'Title', ref: ['type' => 'block', 'id' => '2S8X-AXQ6']);
		$detection = new TimelineEntry('d1', 100, 'detection', 'Group', 'Title', ref: ['type' => 'detection', 'id' => '14']);

		$this->assertSame('2S8X-AXQ6', $block->quotableReference());
		$this->assertNull($detection->quotableReference());
		$this->assertSame(['type' => 'detection', 'id' => '14'], $detection->toArray()['ref'], 'the export keeps every reference');
	}

	public function testTheSummaryOfAnAccount(): void {
		$followUp = 'Check the app passwords.';
		$report = $this->builder([
			0 => $this->source('detection', [
				self::entry('d1', 100, severity: 'high', enforced: true, done: ['Blocked 198.51.100.7.', 'Notified the admins.'], categories: [DataCategory::AccountContent], address: '198.51.100.7', group: 'Second factor failed'),
				self::entry('d2', 200, severity: 'low', enforced: false, done: ['Blocked 203.0.113.9.'], followUp: 'Decide.', address: '203.0.113.9', group: 'Second factor failed'),
				self::entry('d3', 300, severity: 'medium', enforced: true, done: ['Notified the admins.'], address: '198.51.100.7', group: 'Credential stuffing'),
			]),
			2 => $this->source('app_password', [
				self::entry('a1', 50, 'app_password', categories: [DataCategory::ConnectedDevices], followUp: $followUp, group: 'App passwords created'),
				self::entry('a2', 400, 'app_password', categories: [DataCategory::ConnectedDevices], followUp: $followUp, group: 'App passwords created'),
			]),
		])->build($this->user(), 'admin', $this->l);
		$summary = $report->summary;

		$this->assertSame('Nextcloud recorded 5 events about the account alice between @' . (self::NOW - 86400) . ' and @' . self::NOW . '. Detections: 3 (acted on: 2, only observed: 1).', $summary->headline);
		$this->assertSame(['App passwords created: 2 times, the first at @50', 'Second factor failed: 2 times, the first at @100', 'Credential stuffing: once, at @300'], $summary->happened);
		$this->assertSame(50, $summary->startedAt);
		$this->assertSame(100, $summary->foundAt, 'found when the first detection was made');
		$this->assertSame(400, $summary->lastActivityAt);
		$this->assertSame(['The account alice (Alice Liddell)', 'Addresses involved: 198.51.100.7, 203.0.113.9'], $summary->affected);
		$this->assertSame([DataCategory::AccountContent->label($this->l), DataCategory::ConnectedDevices->label($this->l)], $summary->dataCategories);
		$this->assertNull($summary->dataNote);
		$this->assertSame(['Blocked 198.51.100.7.', 'Notified the admins.'], $summary->measures, 'what observed detections would have done is no measure, and nothing is repeated');
		$this->assertSame([$followUp, 'Decide.'], $summary->openItems);
		$this->assertSame(['entries' => 5, 'detections' => 3, 'enforced' => 2, 'observed' => 1], $summary->counts);
		$this->assertSame('Alice Liddell', $report->displayName);
		$this->assertSame('https://cloud.example.org', $report->server);
		$this->assertSame('admin', $report->generatedBy);
	}

	public function testTheSummaryOfAnAddressNamesTheAccountsAndSaysWhenNothingWasOpened(): void {
		$entries = [];
		for ($i = 1; $i <= 12; $i++) {
			$entries[] = self::entry('d' . $i, $i, severity: 'medium', enforced: true, accounts: ['user' . $i]);
		}
		$query = IncidentQuery::forAddress('2001:db8::7', self::NOW - 3600, self::NOW, self::NOW);
		$summary = $this->builder([0 => $this->source('detection', $entries)])->build($query, 'admin', $this->l)->summary;

		$this->assertSame('The address 2001:db8::7 and its network 2001:db8::/64', $summary->affected[0]);
		$this->assertSame('Accounts involved: user1, user2, user3, user4, user5, user6, user7, user8, user9, user10 and 2 more', $summary->affected[1]);
		$this->assertSame([], $summary->dataCategories);
		$this->assertSame('No sign that data was opened: only failed attempts and blocks were recorded.', $summary->dataNote);
	}

	public function testAnEmptyReportSaysSo(): void {
		$report = $this->builder([])->build($this->user(), 'occ', $this->l);
		$this->assertSame([], $report->entries);
		$this->assertStringStartsWith('Nextcloud recorded nothing about the account alice', $report->summary->headline);
		$this->assertNull($report->summary->startedAt);
		$this->assertNull($report->summary->dataNote);
		$this->assertSame([], $report->summary->measures);
	}

	public function testTheJsonHasTheSchemaVersionAndNoInternalFields(): void {
		$report = $this->builder([0 => $this->source('detection', [self::entry('d1', 10, categories: [DataCategory::Administration], followUp: 'x')])])->build($this->user(), 'admin', $this->l);
		$data = $report->toArray();
		$this->assertSame(IncidentReport::SCHEMA_VERSION, $data['schemaVersion']);
		$this->assertSame(['type' => 'user', 'value' => 'alice', 'displayName' => 'Alice Liddell'], $data['subject']);
		$this->assertSame(['since' => self::NOW - 86400, 'until' => self::NOW], $data['period']);
		$this->assertArrayNotHasKey('categories', $data['entries'][0]);
		$this->assertArrayNotHasKey('followUp', $data['entries'][0]);
	}

	public function testMeasuresAreCapped(): void {
		$entries = [];
		for ($i = 1; $i <= 35; $i++) {
			$entries[] = self::entry('d' . $i, $i, enforced: true, done: ['Measure ' . $i]);
		}
		$measures = $this->builder([0 => $this->source('detection', $entries)])->build($this->user(), 'admin', $this->l)->summary->measures;
		$this->assertCount(31, $measures);
		$this->assertSame('… and 5 more, listed on the timeline.', $measures[30]);
	}
}
