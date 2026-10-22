<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Controller;

use OCA\IntrusionDetection\Admin\BlocklistPresenter;
use OCA\IntrusionDetection\Admin\NotificationOverview;
use OCA\IntrusionDetection\Admin\TrapsOverview;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Blocklist\BlocklistSource;
use OCA\IntrusionDetection\Blocklist\BlocklistSync;
use OCA\IntrusionDetection\Blocklist\ListFormat;
use OCA\IntrusionDetection\Blocklist\SourceEditor;
use OCA\IntrusionDetection\Blocklist\SourceRepository;
use OCA\IntrusionDetection\Blocklist\SyncResult;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Configure\SettingsEditor;
use OCA\IntrusionDetection\Controller\BlocklistApiController;
use OCA\IntrusionDetection\Controller\DecoyApiController;
use OCA\IntrusionDetection\Controller\NotificationApiController;
use OCA\IntrusionDetection\Decoy\DecoyService;
use OCA\IntrusionDetection\Definition\InvalidParamException;
use OCA\IntrusionDetection\Notification\TestAlert;
use OCA\IntrusionDetection\Traps\ReservedNames;
use OCP\AppFramework\Http;
use OCP\AppFramework\OCS\OCSNotFoundException;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IUser;
use OCP\IUserSession;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;

/**
 * Validation and the audit trail of the controllers behind the Blocks,
 * Decoys, Notifications and Data and privacy tabs.
 */
class AdminTabControllersTest extends TestCase {
	private IL10N $l;
	private IUserSession&MockObject $session;
	private AuditLogger&MockObject $audit;

	protected function setUp(): void {
		parent::setUp();
		$this->l = Server::get(IFactory::class)->get('intrusion_detection', 'en');
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn('alice');
		$this->session = $this->createMock(IUserSession::class);
		$this->session->method('getUser')->willReturn($user);
		$this->audit = $this->createMock(AuditLogger::class);
	}

	private static function source(string $id, bool $enabled): BlocklistSource {
		return new BlocklistSource($id, $id, 'https://lists.example.org/' . $id, ListFormat::Cidr, BlocklistSource::PURPOSE_DENY, BlocklistSource::MODE_OBSERVE, $enabled, null, false);
	}

	/**
	 * @return array{BlocklistApiController, SourceEditor&MockObject, BlocklistSync&MockObject}
	 */
	private function blocklists(?BlocklistSource $existing = null): array {
		$editor = $this->createMock(SourceEditor::class);
		$sources = $this->createMock(SourceRepository::class);
		$sources->method('get')->willReturn($existing);
		$sync = $this->createMock(BlocklistSync::class);
		$presenter = $this->createMock(BlocklistPresenter::class);
		$presenter->method('list')->willReturn(['id' => 'corp']);
		$controller = new BlocklistApiController($this->createMock(IRequest::class), $this->l, $this->session, $presenter, $editor, $sources, $sync, $this->audit);
		return [$controller, $editor, $sync];
	}

	public function testANewListIsSwitchedOnAndErrorsNameTheirField(): void {
		[$controller, $editor] = $this->blocklists();
		$editor->expects($this->exactly(2))->method('set')
			->willReturnCallback(function (string $id, array $changes, string $actor): BlocklistSource {
				$this->assertSame('alice', $actor);
				$this->assertTrue($changes['enabled']);
				$this->assertSame('cidr', $changes['format']);
				if ($id === 'bad') {
					throw new InvalidParamException('url_refused');
				}
				return self::source($id, true);
			});
		$this->assertSame(['id' => 'corp'], $controller->create(' corp ', ' https://lists.example.org/x ', 'deny')->getData());
		$refused = $controller->create('bad', 'https://localhost/x', 'deny');
		$this->assertSame(Http::STATUS_BAD_REQUEST, $refused->getStatus());
		$this->assertSame('url', $refused->getData()['param']);
	}

	public function testAnIntervalOfZeroMeansTheDefault(): void {
		[$controller, $editor] = $this->blocklists(self::source('corp', true));
		$editor->expects($this->once())->method('set')->with('corp', ['enabled' => false, 'interval' => null], 'alice')->willReturn(self::source('corp', false));
		$controller->update('corp', false, null, 0);
	}

	public function testUnknownListsAreNotFound(): void {
		[$controller] = $this->blocklists();
		$this->expectException(OCSNotFoundException::class);
		$controller->remove('nothing');
	}

	public function testSyncNowOnlyForEnabledListsAndAudited(): void {
		[$controller, , $sync] = $this->blocklists(self::source('corp', false));
		$sync->expects($this->never())->method('sync');
		$this->assertSame('list_disabled', $controller->syncNow('corp')->getData()['reason']);

		[$controller, , $sync] = $this->blocklists(self::source('corp', true));
		$sync->expects($this->once())->method('sync')->with('corp')->willReturn([new SyncResult('corp', SyncResult::FAILED, 'http_error', status: 503)]);
		$this->audit->expects($this->once())->method('log')->with('blocklist %s downloaded by %s: %s', ['list' => 'corp', 'actor' => 'alice', 'outcome' => 'failed']);
		$data = $controller->syncNow('corp')->getData();
		$this->assertSame('failed', $data['result']['outcome']);
		$this->assertSame('lists.example.org answered with HTTP status 503', $data['result']['errorText'], 'the server and the status of the list');
	}

	/**
	 * @return array{DecoyApiController, CheckSettings&MockObject, SettingsEditor&MockObject, ReservedNames&MockObject}
	 */
	private function decoys(): array {
		$settings = $this->createMock(CheckSettings::class);
		$editor = $this->createMock(SettingsEditor::class);
		$reserved = $this->createMock(ReservedNames::class);
		$overview = $this->createMock(TrapsOverview::class);
		$overview->method('trapPaths')->willReturn(['custom' => []]);
		$controller = new DecoyApiController($this->createMock(IRequest::class), $this->l, $this->session, $overview, $this->createMock(DecoyService::class), $reserved, $settings, $editor, $this->audit);
		return [$controller, $settings, $editor, $reserved];
	}

	public function testTrapPathChangesAreSavedTogetherAndAudited(): void {
		[$controller, $settings, $editor] = $this->decoys();
		$settings->method('paramList')->willReturn(['/old/*', '/gone']);
		$editor->expects($this->once())->method('updateCheck')
			->with('trap_url', null, ['paths' => ['/old/*', '/new'], 'autodiscover' => true], null)
			->willReturn(['params' => ['paths' => ['/old/*', '/new'], 'autodiscover' => true]]);
		$this->audit->expects($this->once())->method('log')->with($this->anything(), [
			'actor' => 'alice', 'added' => '/new', 'removed' => '/gone', 'builtin' => 'unchanged', 'autodiscover' => 'on',
		]);
		$controller->updateTrapPaths(['/NEW', 42], ['/gone'], null, true);
	}

	public function testAnInvalidTrapPathSavesNothing(): void {
		[$controller, $settings, $editor] = $this->decoys();
		$settings->method('paramList')->willReturn([]);
		$editor->method('updateCheck')->willThrowException(new InvalidParamException('nextcloud_path', ['param' => 'paths', 'item' => '/apps']));
		$this->audit->expects($this->never())->method('log');
		$response = $controller->updateTrapPaths(['/apps']);
		$this->assertSame(Http::STATUS_BAD_REQUEST, $response->getStatus());
		$this->assertSame('paths', $response->getData()['param']);
	}

	public function testTrapPathsThatChangeNothingAreNotAudited(): void {
		[$controller, $settings, $editor] = $this->decoys();
		$settings->method('paramList')->willReturn(['/old']);
		$editor->method('updateCheck')->willReturn([]);
		$this->audit->expects($this->never())->method('log');
		$this->assertSame(Http::STATUS_OK, $controller->updateTrapPaths(['/old'])->getStatus());
	}

	public function testTooManyChangesAtOnceAreRefused(): void {
		[$controller, , , $reserved] = $this->decoys();
		$reserved->expects($this->never())->method('change');
		$this->assertSame('too_many_items', $controller->updateReservedNames(array_map(static fn (int $i): string => 'name' . $i, range(1, 101)))->getData()['reason']);
	}

	public function testTheTestAlertGoesToTheAdminWhoAsksAndIsAudited(): void {
		$alert = $this->createMock(TestAlert::class);
		$alert->expects($this->once())->method('send')->with($this->session->getUser())->willReturn(['bell' => true, 'email' => 'sent', 'address' => 'alice@example.org']);
		$this->audit->expects($this->once())->method('log')->with('test alert sent to %s: email %s', ['actor' => 'alice', 'email' => 'sent']);
		$controller = new NotificationApiController($this->createMock(IRequest::class), $this->l, $this->session, $this->createMock(NotificationOverview::class), $alert, $this->audit);
		$this->assertSame('sent', $controller->test()->getData()['email']);
	}

}
