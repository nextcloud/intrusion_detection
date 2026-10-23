<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Address\AddressCache;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Blocklist\BlocklistOverview;
use OCA\IntrusionDetection\Blocklist\BlocklistSource;
use OCA\IntrusionDetection\Blocklist\Db\BlocklistStatMapper;
use OCA\IntrusionDetection\Blocklist\SourceEditor;
use OCA\IntrusionDetection\Blocklist\SourceRepository;
use OCA\IntrusionDetection\Blocklist\UrlPolicy;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Definition\InvalidParamException;
use OCA\IntrusionDetection\State\AppState;
use OCP\Server;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;

#[Group('DB')]
class SourceEditorTest extends IntegrationTestCase {
	/** @var list<array{string, array<string, scalar|null>}> */
	private array $audited = [];

	public function testABuiltInListIsSwitchedOnAndBackToItsDefault(): void {
		$version = Server::get(AppState::class)->get(AddressCache::VERSION_STATE);
		$source = $this->editor()->set('spamhaus_drop_v4', ['enabled' => true, 'mode' => 'observe'], 'admin');
		$this->assertTrue($source->enabled);
		$this->assertSame('observe', $source->mode);
		$this->assertTrue(Server::get(SourceRepository::class)->get('spamhaus_drop_v4')?->enabled);
		$this->assertNotSame($version, Server::get(AppState::class)->get(AddressCache::VERSION_STATE), 'Cached verdicts are invalidated');
		$this->assertStringContainsString('spamhaus_drop_v4', json_encode($this->audited));
		$this->assertStringContainsString('admin', json_encode($this->audited));

		$this->editor()->set('tor_exits', ['interval' => 7200], 'admin');
		$this->assertSame(7200, Server::get(SourceRepository::class)->get('tor_exits')?->interval);
		$this->editor()->set('tor_exits', ['interval' => null], 'admin');
		$this->assertSame(3600, Server::get(SourceRepository::class)->get('tor_exits')?->interval);

		$this->editor()->set('spamhaus_drop_v4', ['enabled' => false, 'mode' => 'protect'], 'admin');
		$this->assertSame('[]', $this->appConfig->getValueString(Application::APP_ID, GlobalSettings::BLOCKLIST_SOURCES), 'Untouched built-in lists need no entry');
	}

	public function testACustomListIsCreatedChangedAndRemoved(): void {
		$source = $this->editor()->set('office_block', ['url' => 'https://lists.example.org/block.txt', 'purpose' => 'deny', 'enabled' => true], 'occ');
		$this->assertFalse($source->builtin);
		$this->assertSame(BlocklistSource::MODE_OBSERVE, $source->mode);
		$this->editor()->set('office_block', ['mode' => 'protect'], 'occ');
		$this->assertSame('protect', Server::get(SourceRepository::class)->get('office_block')?->mode);
		$this->assertSame('https://lists.example.org/block.txt', Server::get(SourceRepository::class)->get('office_block')?->url);

		$this->editor()->remove('office_block', 'occ');
		$this->assertNull(Server::get(SourceRepository::class)->get('office_block'));
	}

	/**
	 * @return array<string, array{string, array<string, mixed>, string}>
	 */
	public static function refused(): array {
		return [
			'plain http' => ['mine', ['url' => 'http://lists.example.org/x.txt', 'purpose' => 'deny'], 'url_refused'],
			'loopback' => ['mine', ['url' => 'https://127.0.0.1/x.txt', 'purpose' => 'deny'], 'url_refused'],
			'localhost' => ['mine', ['url' => 'https://localhost/x.txt', 'purpose' => 'deny'], 'url_refused'],
			'private network' => ['mine', ['url' => 'https://192.168.10.1/x.txt', 'purpose' => 'deny'], 'url_refused'],
			'credentials' => ['mine', ['url' => 'https://user:pw@lists.example.org/x.txt', 'purpose' => 'deny'], 'url_refused'],
			'no address' => ['mine', ['purpose' => 'deny'], 'list_needs_url'],
			'unknown purpose' => ['mine', ['url' => 'https://lists.example.org/x.txt', 'purpose' => 'ads'], 'not_a_choice'],
			'unknown format' => ['mine', ['url' => 'https://lists.example.org/x.txt', 'purpose' => 'deny', 'format' => 'xml'], 'not_a_choice'],
			'unknown mode' => ['spamhaus_drop_v4', ['mode' => 'block'], 'not_a_choice'],
			'interval too short' => ['spamhaus_drop_v4', ['interval' => 60], 'too_small'],
			'interval too long' => ['spamhaus_drop_v4', ['interval' => 30 * 86400], 'too_large'],
			'bad id' => ['Mine!', ['url' => 'https://lists.example.org/x.txt', 'purpose' => 'deny'], 'invalid_list_id'],
			'built-in address' => ['spamhaus_drop_v4', ['url' => 'https://lists.example.org/x.txt'], 'builtin_list'],
			'built-in purpose' => ['aws', ['purpose' => 'deny'], 'builtin_list'],
		];
	}

	/**
	 * @param array<string, mixed> $changes
	 */
	#[DataProvider('refused')]
	public function testInvalidChangesAreRefusedAndNothingIsSaved(string $id, array $changes, string $reason): void {
		try {
			$this->editor()->set($id, $changes, 'admin');
			$this->fail('Expected ' . $reason);
		} catch (InvalidParamException $e) {
			$this->assertSame($reason, $e->reason);
		}
		$this->assertSame('[]', $this->appConfig->getValueString(Application::APP_ID, GlobalSettings::BLOCKLIST_SOURCES, '[]'));
		$this->assertSame([], $this->audited);
	}

	public function testBuiltInListsCannotBeRemoved(): void {
		$this->expectExceptionObject(new InvalidParamException('builtin_list'));
		$this->editor()->remove('spamhaus_drop_v4', 'admin');
	}

	public function testTheNumberOfListsIsLimited(): void {
		$stored = [];
		for ($i = count(Server::get(SourceRepository::class)->all()); $i < SourceRepository::MAX_SOURCES; $i++) {
			$stored[] = ['id' => 'list_' . $i, 'url' => 'https://lists.example.org/' . $i, 'purpose' => 'deny'];
		}
		$this->settingsEditor()->setGlobal(GlobalSettings::BLOCKLIST_SOURCES, json_encode($stored));
		$this->expectExceptionObject(new InvalidParamException('too_many_lists', ['param' => 'id', 'max' => SourceRepository::MAX_SOURCES]));
		$this->editor()->set('one_more', ['url' => 'https://lists.example.org/more', 'purpose' => 'deny'], 'admin');
	}

	public function testTheOverviewShowsMatchesPerListAndDay(): void {
		$stats = Server::get(BlocklistStatMapper::class);
		$today = gmdate('Y-m-d');
		$stats->record('spamhaus_drop_v4', $today, '198.51.100.7');
		$stats->record('spamhaus_drop_v4', $today, '198.51.100.8');
		$stats->record('spamhaus_drop_v4', gmdate('Y-m-d', time() - 20 * 86400), '198.51.100.9');
		$matches = Server::get(BlocklistOverview::class)->matches(14);
		$this->assertSame([['day' => $today, 'matches' => 2, 'sample' => ['198.51.100.7', '198.51.100.8']]], $matches['spamhaus_drop_v4']);
		$this->assertSame([], $matches['aws'], 'Network lists are listed too, without matches so far');

		$lists = Server::get(BlocklistOverview::class)->lists();
		$drop = array_values(array_filter($lists, static fn (array $l): bool => $l['id'] === 'spamhaus_drop_v4'))[0];
		$this->assertSame(Server::get(SourceRepository::class)->reference('spamhaus_drop_v4'), $drop['reference']);
		$this->assertSame('https://www.spamhaus.org/drop/terms/', $drop['termsUrl']);
		$this->assertFalse($drop['stale']);
	}

	private function editor(): SourceEditor {
		$audit = $this->createMock(AuditLogger::class);
		$audit->method('log')->willReturnCallback(function (string $message, array $parameters = []): void {
			$this->audited[] = [$message, $parameters];
		});
		return new SourceEditor(Server::get(SourceRepository::class), Server::get(UrlPolicy::class), $this->settingsEditor(), Server::get(AddressCache::class), $audit);
	}
}
