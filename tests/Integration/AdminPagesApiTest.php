<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffing;
use OCA\IntrusionDetection\Check\Checks\InjectionProbe;
use OCA\IntrusionDetection\Check\Checks\TrapUrl;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Controller\AdminApiController;
use OCA\IntrusionDetection\Controller\BlocklistApiController;
use OCA\IntrusionDetection\Controller\DecoyApiController;
use OCA\IntrusionDetection\Controller\NotificationApiController;
use OCA\IntrusionDetection\Controller\PayloadApiController;
use OCA\IntrusionDetection\Controller\PrivacyApiController;
use OCA\IntrusionDetection\Controller\SimulationApiController;
use OCA\IntrusionDetection\Detection\Simulator;
use OCA\IntrusionDetection\Traps\TrapNameCollisions;
use OCP\AppFramework\Http;
use OCP\AppFramework\OCS\OCSNotFoundException;
use OCP\IUserManager;
use OCP\IUserSession;
use OCP\Notification\IManager as INotificationManager;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * The tabs of the admin page beyond the overview, checks and blocks, through
 * the controllers as the page calls them, against the real database.
 */
#[Group('DB')]
class AdminPagesApiTest extends IntegrationTestCase {
	private const USERS = ['ids_admin', 'ids_alice', 'ids_root2'];

	private DecoyApiController $decoys;
	private BlocklistApiController $blocklists;
	private PrivacyApiController $privacy;
	private PayloadApiController $payload;
	private SimulationApiController $simulation;
	private NotificationApiController $notifications;
	private AdminApiController $admin;

	protected function setUp(): void {
		parent::setUp();
		$users = Server::get(IUserManager::class);
		foreach (['ids_admin', 'ids_alice'] as $uid) {
			if (!$users->userExists($uid)) {
				$users->createUser($uid, 'Ids-Test-Password-2026');
			}
		}
		Server::get(IUserSession::class)->setUser($users->get('ids_admin'));
		$container = (new Application())->getContainer();
		$this->decoys = $container->get(DecoyApiController::class);
		$this->blocklists = $container->get(BlocklistApiController::class);
		$this->privacy = $container->get(PrivacyApiController::class);
		$this->payload = $container->get(PayloadApiController::class);
		$this->simulation = $container->get(SimulationApiController::class);
		$this->notifications = $container->get(NotificationApiController::class);
		$this->admin = $container->get(AdminApiController::class);
	}

	protected function tearDown(): void {
		Server::get(IUserSession::class)->setUser(null);
		foreach (self::USERS as $uid) {
			Server::get(IUserManager::class)->get($uid)?->delete();
		}
		parent::tearDown();
	}

	public function testADecoySecretIsReturnedOnceAndNeverAgain(): void {
		$response = $this->decoys->create('old backup script on nas01', 'backup-svc', 'token');
		$this->assertSame(Http::STATUS_OK, $response->getStatus());
		$this->assertSame('no-store', $response->getHeaders()['Cache-Control'] ?? null);
		$secret = $response->getData()['secret'];
		$this->assertMatchesRegularExpression('/^[A-Za-z0-9]{72}$/', $secret);
		$this->assertSame('backup-svc', $response->getData()['decoy']['loginName']);

		$hmac = (string)$this->db->getQueryBuilder()->select('secret_hmac')->from('ids_decoys')->executeQuery()->fetchOne();
		$this->assertNotSame('', $hmac);

		// No read of the page returns the secret or its fingerprint again.
		foreach ($this->everyRead() as $name => $data) {
			$json = json_encode($data, JSON_THROW_ON_ERROR);
			$this->assertStringNotContainsString($secret, $json, $name);
			$this->assertStringNotContainsString($hmac, $json, $name);
			$this->assertStringNotContainsString('secretHmac', $json, $name);
			$this->assertStringNotContainsString('secret_hmac', $json, $name);
		}
		// And it is in no table.
		foreach (self::TABLES as $table) {
			foreach ($this->db->getQueryBuilder()->select('*')->from($table)->executeQuery()->fetchAll() as $row) {
				$this->assertStringNotContainsString($secret, json_encode($row, JSON_THROW_ON_ERROR), $table);
			}
		}
		$listed = $this->decoys->index()->getData()['decoys'];
		$this->assertCount(1, $listed);
		$this->assertArrayNotHasKey('secret', $listed[0]);
	}

	public function testDecoysAreValidated(): void {
		$this->assertSame('secretFormat', $this->decoys->create('label', '', 'plain')->getData()['param']);
		$this->assertSame('login_name', $this->decoys->create('label', 'IDS_Alice')->getData()['param'], 'An existing account cannot be a decoy name');
		$this->assertSame('label', $this->decoys->create("\n  ")->getData()['param']);
		$this->assertSame(0, (int)$this->db->getQueryBuilder()->select($this->db->getQueryBuilder()->func()->count('*'))->from('ids_decoys')->executeQuery()->fetchOne());
	}

	public function testDeletingADecoyTwiceIsNotFound(): void {
		$id = $this->decoys->create('label')->getData()['decoy']['id'];
		$this->assertSame(['deleted' => $id], $this->decoys->delete($id)->getData());
		$this->expectException(OCSNotFoundException::class);
		$this->decoys->delete($id);
	}

	public function testReservedNamesAreChangedInOneGoAndCollisionsShowUp(): void {
		$names = $this->decoys->updateReservedNames(['Root', 'ids_root2'])->getData();
		$this->assertSame(['root', 'ids_root2'], $names['names']);
		$this->assertNotContains('root', $names['suggestions']);

		$refused = $this->decoys->updateReservedNames(['webmaster', 'ids_alice'], ['root']);
		$this->assertSame(Http::STATUS_BAD_REQUEST, $refused->getStatus());
		$this->assertSame('existing_user', $refused->getData()['reason']);
		$this->assertSame(['root', 'ids_root2'], $this->decoys->index()->getData()['reservedNames']['names'], 'Nothing was saved');

		// The name becomes an account later, as with LDAP; the hourly job finds it.
		Server::get(IUserManager::class)->createUser('ids_root2', 'Ids-Test-Password-2026');
		$this->assertSame([], $this->decoys->index()->getData()['reservedNames']['collisions'], 'Pages read the stored lookup');
		Server::get(TrapNameCollisions::class)->refresh();
		$this->assertSame(['ids_root2'], $this->decoys->index()->getData()['reservedNames']['collisions']);
		$problems = array_column($this->admin->status()->getData()['problems'], null, 'id');
		$this->assertSame('error', $problems['trap_name_collision']['level']);
		$this->assertSame('#blocks-decoys', $problems['trap_name_collision']['url']);
		$this->assertNotEmpty($problems['trap_name_collision']['fix']);

		// Any later change releases the name that no longer works.
		$this->assertSame(['root', 'webmaster'], $this->decoys->updateReservedNames(['webmaster'])->getData()['names']);
	}

	public function testTrapPathsAreValidatedAndRoutedByTheSnippets(): void {
		$refused = $this->decoys->updateTrapPaths(['/index.php/apps/files']);
		$this->assertSame(Http::STATUS_BAD_REQUEST, $refused->getStatus());
		$this->assertSame('nextcloud_path', $refused->getData()['reason']);

		$paths = $this->decoys->updateTrapPaths(['/Old-Admin/*', '/a{b}'], [], null, true)->getData();
		$this->assertSame(['/old-admin/*', '/a{b}'], $paths['custom']);
		$this->assertTrue($paths['autodiscover']);
		$this->assertSame(['/a{b}'], $paths['snippetsSkipped']);
		$snippets = array_column($paths['snippets'], 'content', 'id');
		$this->assertStringContainsString('|old-admin/', $snippets['nginx']);
		$this->assertStringContainsString('autodiscover/autodiscover\.xml', $snippets['apache']);
		$this->assertStringNotContainsString('{b}', $snippets['nginx'] . $snippets['apache']);

		$after = $this->decoys->updateTrapPaths([], ['/a{b}'], false)->getData();
		$this->assertSame(['/old-admin/*'], $after['custom']);
		$this->assertFalse($after['builtinEnabled']);
		$this->assertStringNotContainsString('wp-login', array_column($after['snippets'], 'content', 'id')['nginx']);
	}

	public function testCustomListsAreValidatedAndBuiltInOnesProtected(): void {
		$local = $this->blocklists->create('intranet', 'https://localhost/list.txt', 'deny');
		$this->assertSame(Http::STATUS_BAD_REQUEST, $local->getStatus());
		$this->assertSame('url', $local->getData()['param']);
		$this->assertSame('url', $this->blocklists->create('plain', 'http://lists.example.org/x.txt', 'deny')->getData()['param']);
		$this->assertSame('id', $this->blocklists->create('Bad Name', 'https://lists.example.org/x.txt', 'deny')->getData()['param']);
		$this->assertSame('list_exists', $this->blocklists->create('aws', 'https://lists.example.org/x.txt', 'hosting')->getData()['reason']);

		$list = $this->blocklists->create('corp_feed', 'https://lists.example.org/x.txt', 'deny', 'cidr', 'observe', 3600)->getData();
		$this->assertSame('observe', $list['mode']);
		$this->assertTrue($list['enabled']);
		$this->assertSame(3600, $list['interval']);
		$this->assertTrue($list['customInterval']);

		$this->assertSame(Http::STATUS_BAD_REQUEST, $this->blocklists->remove('aws')->getStatus(), 'Built-in lists are switched off, not removed');
		$this->assertSame(['removed' => 'corp_feed'], $this->blocklists->remove('corp_feed')->getData());

		$aws = $this->blocklists->update('aws', true, null, 7200)->getData();
		$this->assertTrue($aws['enabled']);
		$this->assertSame(7200, $aws['interval']);
		$this->assertSame(21600, $this->blocklists->update('aws', null, null, 0)->getData()['interval'], 'Back to the default interval');
		$this->assertSame('protect', $this->blocklists->update('spamhaus_drop_v4', null, 'protect')->getData()['mode']);
		$this->assertSame('interval', $this->blocklists->update('aws', null, null, 60)->getData()['param']);

		$this->assertSame('list_disabled', $this->blocklists->syncNow('firehol_level1')->getData()['reason']);
		$this->expectException(OCSNotFoundException::class);
		$this->blocklists->update('no_such_list', true);
	}

	public function testTheBlocklistsExplainTheirCheckAndTheExportItsDirectory(): void {
		$lists = $this->blocklists->lists()->getData();
		$this->assertSame('blocklist_match', $lists['check']['id']);
		$this->assertSame('off', $lists['check']['mode']['effective']);
		$this->assertContains('cidr', $lists['formats']);
		$spamhaus = array_column($lists['lists'], null, 'id')['spamhaus_drop_v4'];
		$this->assertMatchesRegularExpression('/^LIST-[A-Z0-9]{6}$/', (string)$spamhaus['reference']);

		$export = $this->blocklists->export()->getData();
		$this->assertSame('intrusion_detection.export_dir', $export['configKey']);
		$this->assertSame(['nftables', 'nft_loader', 'systemd_path', 'systemd_service', 'ipset', 'fail2ban_filter', 'fail2ban_jail'], array_column($export['snippets'], 'id'));
		if ($export['directory'] === null) {
			$this->assertSame('not_configured', $export['error']);
			$this->assertNotEmpty($export['errorText']);
		}
	}

	public function testPrivacyListsWhatTheInstalledChecksStore(): void {
		$data = $this->privacy->index()->getData();
		$stored = array_column($data['stored'], null, 'id');
		foreach (['failed_attempts', 'detections', 'bans', 'decoys', 'request_excerpts', 'alert_counters'] as $kind) {
			$this->assertArrayHasKey($kind, $stored);
			$this->assertNotSame('', $stored[$kind]['name']);
			$this->assertNotSame('', $stored[$kind]['why']);
		}
		$this->assertSame('1 hour', $stored['failed_attempts']['retention']);
		$this->assertStringContainsString('{retention_detections_days}', $stored['detections']['retention']);
		$this->assertContains('Credential stuffing', $stored['failed_attempts']['checks']);
		$this->assertSame('ids_reset_suppressions', $stored['reset_suppressions']['where']);
		$this->assertStringContainsString('only be told about inside Nextcloud', $stored['account_state']['what'], 'The login notice time is a user value too');
		$this->assertStringContainsString('at most 24 hours', $stored['flags']['retention']);
		$outgoing = array_column($data['outgoing'], null, 'id');
		$this->assertFalse($outgoing['blocklists']['active']);
		$this->assertCount(2, $data['gdpr']);

		// The page fills the retention placeholders live from the settings it has.
		$settings = array_column($this->admin->settings()->getData()['settings'], 'name');
		foreach ($data['stored'] as $row) {
			preg_match_all('/\{([a-z0-9_]+)\}/', $row['retention'], $m);
			foreach ($m[1] as $placeholder) {
				$this->assertContains($placeholder, $settings, $row['id']);
			}
		}
	}

	public function testTestingAUrlShowsEveryStepWithoutRecordingAnything(): void {
		$result = $this->payload->test("/index.php/apps/files/?data=JyBPUiAnMSc9JzE=&password=x' OR 1=1")->getData();
		$this->assertTrue($result['fires']);
		$values = array_column($result['values'], null, 'name');
		$this->assertSame(["' OR '1'='1"], $values['data']['decoded']);
		$this->assertSame('secret', $values['password']['skipped']);
		$this->assertArrayNotHasKey('normalised', $values['password'], 'Password fields are never shown');
		$this->assertSame(Http::STATUS_BAD_REQUEST, $this->payload->test('  ')->getStatus());
		foreach (self::TABLES as $table) {
			$this->assertSame(0, $this->rows($table), $table);
		}
	}

	public function testSignaturesCanBeCheckedBeforeSaving(): void {
		$checked = array_column($this->payload->checkSignatures(['2:union\s+distinct', '(', '.*', 42])->getData()['entries'], null, 'entry');
		$this->assertCount(3, $checked);
		$this->assertNull($checked['2:union\s+distinct']['problem']);
		$this->assertSame(2, $checked['2:union\s+distinct']['weight']);
		$this->assertSame('union\s+distinct', $checked['2:union\s+distinct']['pattern']);
		$this->assertSame('does_not_compile', $checked['(']['problem']);
		$this->assertSame('matches_everything', $checked['.*']['problem']);
		$this->assertSame(Http::STATUS_BAD_REQUEST, $this->payload->checkSignatures(array_fill(0, 51, 'x'))->getStatus());

		$this->admin->updateCheck(InjectionProbe::ID, null, null, ['disabled_signatures' => ['sql_sleep'], 'custom_signatures' => ['2:union\s+distinct']]);
		$catalog = $this->payload->signatures()->getData();
		$this->assertFalse(array_column($catalog['signatures'], null, 'id')['sql_sleep']['enabled']);
		$this->assertSame('sql', array_column($catalog['signatures'], null, 'id')['sql_sleep']['group']);
		$this->assertSame(['2:union\s+distinct'], array_column($catalog['custom'], 'entry'));
	}

	public function testSimulatingWritesNothing(): void {
		$result = $this->simulation->simulate(CredentialStuffing::ID)->getData();
		$this->assertSame(Simulator::TEST_ADDRESS, $result['testAddress']);
		$this->assertStringContainsString(Simulator::TEST_ADDRESS, implode(' ', $result['narrative']['happened']));
		$this->assertTrue($result['acts']);
		$this->assertContains('ban', array_column($result['responses'], 'type'));
		$this->assertStringContainsString('4 hours', array_column($result['responses'], 'text', 'type')['ban']);
		foreach (self::TABLES as $table) {
			$this->assertSame(0, $this->rows($table), $table);
		}
		$this->assertSame(TrapUrl::ID, $this->simulation->simulate(TrapUrl::ID)->getData()['check']);
		$this->expectException(OCSNotFoundException::class);
		$this->simulation->simulate(InjectionProbe::ID);
	}

	public function testTheTestAlertReachesTheAdminWhoAsks(): void {
		Server::get(INotificationManager::class)->registerApp(CapturingNotificationApp::class);
		CapturingNotificationApp::$notifications = [];
		$result = $this->notifications->test()->getData();
		$this->assertTrue($result['bell']);
		$this->assertSame('no_address', $result['email'], 'The test admin has no email address');
		// The capturing app may be registered more than once in a test run, so each notification is counted once.
		$sent = array_values(array_combine(array_map(spl_object_id(...), CapturingNotificationApp::$notifications), CapturingNotificationApp::$notifications));
		$this->assertCount(1, $sent);
		$this->assertSame('ids_admin', $sent[0]->getUser());
		$this->assertSame('test_alert', $sent[0]->getSubject());

		$overview = $this->notifications->index()->getData();
		$this->assertSame('ids_admin', $overview['me']['uid']);
		$checks = array_column($overview['checks'], null, 'id');
		$this->assertTrue($checks[CredentialStuffing::ID]['admin']);
		$this->assertTrue($checks[CredentialStuffing::ID]['adminAvailable']);
	}

	public function testLearningRemembersWhenItStarted(): void {
		$this->admin->updateLearning('start', 7);
		$started = $this->appConfig->getValueInt(Application::APP_ID, GlobalSettings::LEARNING_STARTED_AT);
		$this->assertEqualsWithDelta(time(), $started, 5);
		$this->admin->updateLearning('extend', 7);
		$this->assertSame($started, $this->appConfig->getValueInt(Application::APP_ID, GlobalSettings::LEARNING_STARTED_AT), 'Extending keeps the start');
		$this->admin->updateLearning('stop');
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::LEARNING_STARTED_AT, 1);
		$this->admin->updateLearning('extend', 3);
		$this->assertEqualsWithDelta(time(), $this->appConfig->getValueInt(Application::APP_ID, GlobalSettings::LEARNING_STARTED_AT), 5, 'Extending a finished period starts a new one');
	}

	/**
	 * Everything the page reads, by endpoint.
	 *
	 * @return array<string, mixed>
	 */
	private function everyRead(): array {
		return [
			'status' => $this->admin->status()->getData(),
			'checks' => $this->admin->checks()->getData(),
			'settings' => $this->admin->settings()->getData(),
			'export settings' => $this->admin->exportSettings()->getData(),
			'decoys' => $this->decoys->index()->getData(),
			'blocklists' => $this->blocklists->lists()->getData(),
			'export' => $this->blocklists->export()->getData(),
			'privacy' => $this->privacy->index()->getData(),
			'notifications' => $this->notifications->index()->getData(),
			'signatures' => $this->payload->signatures()->getData(),
		];
	}

	private function rows(string $table): int {
		$qb = $this->db->getQueryBuilder();
		return (int)$qb->select($qb->func()->count('*'))->from($table)->executeQuery()->fetchOne();
	}
}
