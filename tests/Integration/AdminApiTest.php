<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Admin\DetectionPresenter;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\ManualBlock;
use OCA\IntrusionDetection\Check\Checks\SharedAddress;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Controller\AdminApiController;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Db\AttemptMapper;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Response\BanService;
use OCP\AppFramework\Http;
use OCP\IUserManager;
use OCP\IUserSession;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * The admin API against the real database, through the controller as the
 * page calls it.
 */
#[Group('DB')]
class AdminApiTest extends IntegrationTestCase {
	private const SECRET_FINGERPRINT = '0123456789abcdef0123456789abcdef';
	private const SECRET_NAME_HMAC = 'fedcba9876543210fedcba9876543210';

	private AdminApiController $controller;
	private DetectionMapper $detections;
	private BanMapper $bans;
	private BanService $banService;

	protected function setUp(): void {
		parent::setUp();
		$userManager = Server::get(IUserManager::class);
		if (!$userManager->userExists('ids_admin')) {
			$userManager->createUser('ids_admin', 'Ids-Test-Password-2026');
		}
		if (!$userManager->userExists('ids_alice')) {
			$userManager->createUser('ids_alice', 'Ids-Test-Password-2026')?->setDisplayName('Alice Liddell');
		}
		// The acting admin, without setting up a file system.
		Server::get(IUserSession::class)->setUser($userManager->get('ids_admin'));
		$this->controller = (new Application())->getContainer()->get(AdminApiController::class);
		$this->detections = Server::get(DetectionMapper::class);
		$this->bans = Server::get(BanMapper::class);
		$this->banService = Server::get(BanService::class);
	}

	protected function tearDown(): void {
		Server::get(IUserSession::class)->setUser(null);
		$userManager = Server::get(IUserManager::class);
		foreach (['ids_admin', 'ids_alice'] as $uid) {
			$userManager->get($uid)?->delete();
		}
		parent::tearDown();
	}

	public function testStatusCountsTheLastDay(): void {
		$this->banService->banManually('203.0.113.7', 1, 'test', null);
		$this->banService->banManually('203.0.113.8', 1, 'test', null);
		$this->insertDetection(SharedAddress::ID, 'high', true, '203.0.113.9', 'ids_alice');
		$this->insertDetection(ManualBlock::ID, 'medium', false, '198.51.100.1', null, actions: [['type' => 'ban', 'enforced' => false]]);
		$this->insertDetection(ManualBlock::ID, 'medium', false, '198.51.100.2', null, actions: [['type' => 'notify_admin', 'enforced' => false]]);
		$this->insertDetection(ManualBlock::ID, 'medium', true, '198.51.100.3', null, createdAt: time() - 3 * 86400);

		$status = $this->controller->status()->getData();

		$this->assertSame('protecting', $status['state']);
		$this->assertSame(3, $status['last24h']['detections']);
		$this->assertSame(1, $status['last24h']['enforced']);
		$this->assertSame(2, $status['last24h']['observed']);
		$this->assertSame(2, $status['last24h']['blockedAddresses']);
		$this->assertSame(1, $status['last24h']['wouldHaveBlocked']);
		$this->assertSame(1, $status['last24h']['accounts']);
		$this->assertSame(2, $status['activeBans']);
		$this->assertSame([['id' => 'internal', 'name' => 'Raised by Nextcloud itself', 'enforced' => 1, 'observed' => 2]], $status['last24h']['categories']);
		// The shared-address detection above shows up as a setup problem; the guards are not slow.
		$problems = array_column($status['problems'], 'id');
		$this->assertContains('shared_address', $problems);
		$this->assertNotContains('slow_guards', $problems);
	}

	public function testStatusShowsLearningAndOff(): void {
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::LEARNING_UNTIL, time() + 2 * 86400 + 60);
		$status = $this->controller->status()->getData();
		$this->assertSame('learning', $status['state']);
		$this->assertSame(3, $status['learning']['daysLeft']);

		$this->appConfig->setValueBool(Application::APP_ID, GlobalSettings::ENABLED, false);
		$this->assertSame('off', $this->controller->status()->getData()['state']);
	}

	public function testChecksListOnlyConfigurableChecks(): void {
		$ids = array_column($this->controller->checks()->getData()['checks'], 'id');
		$this->assertNotContains(ManualBlock::ID, $ids);
		$this->assertNotContains(SharedAddress::ID, $ids);
	}

	public function testDetectionsArePagedAndFiltered(): void {
		for ($i = 0; $i < 5; $i++) {
			$this->insertDetection(ManualBlock::ID, 'medium', true, '203.0.113.' . $i, null, createdAt: time() - $i * 60);
		}
		$this->insertDetection(SharedAddress::ID, 'high', false, '198.51.100.7', 'ids_alice', createdAt: time() - 30);

		$page = $this->controller->detections(limit: 2, offset: 1)->getData();
		$this->assertSame(6, $page['total']);
		$this->assertCount(2, $page['detections']);
		// Newest first: the shared-address one is second newest.
		$this->assertSame('198.51.100.7', $page['detections'][0]['ip']);

		$this->assertSame(1, $this->controller->detections(check: SharedAddress::ID)->getData()['total']);
		$this->assertSame(1, $this->controller->detections(severity: 'high,critical')->getData()['total']);
		$this->assertSame(1, $this->controller->detections(mode: 'observed')->getData()['total']);
		$this->assertSame(5, $this->controller->detections(mode: 'enforced')->getData()['total']);
		$this->assertSame(1, $this->controller->detections(user: 'ids_alice')->getData()['total']);
		$this->assertSame(1, $this->controller->detections(address: '203.0.113.3')->getData()['total']);
		$this->assertSame(3, $this->controller->detections(since: time() - 90)->getData()['total']);

		$row = $this->controller->detections(check: SharedAddress::ID)->getData()['detections'][0];
		$this->assertSame('Shared address not blocked', $row['checkName']);
		$this->assertSame('internal', $row['category']);
	}

	public function testDetectionDetailExplainsAndShowsRecentAttemptsWithoutFingerprints(): void {
		$attempts = Server::get(AttemptMapper::class);
		$attempts->insert(AttemptKind::PasswordLogin, '203.0.113.7', '203.0.113.0/24', self::SECRET_NAME_HMAC, 'ids_alice', null, self::SECRET_FINGERPRINT, time() - 120);
		$attempts->insert(AttemptKind::PasswordLogin, '203.0.113.7', '203.0.113.0/24', self::SECRET_NAME_HMAC, null, null, self::SECRET_FINGERPRINT, time() - 60);
		$ban = $this->banService->banManually('203.0.113.7', 1, 'test', null);
		$detection = $this->insertDetection(ManualBlock::ID, 'medium', true, '203.0.113.7', null, facts: [
			'failures' => 14,
			// Checks never store these; the presenter removes them anyway.
			'pw_fp' => self::SECRET_FINGERPRINT,
			'nested' => ['nameHmac' => self::SECRET_NAME_HMAC, 'value' => self::SECRET_FINGERPRINT],
		]);

		$response = $this->controller->detection((int)$detection->getId());
		$detail = $response->getData();
		$json = (string)json_encode($detail);

		$this->assertSame(Http::STATUS_OK, $response->getStatus());
		$this->assertTrue($detail['attemptsAvailable']);
		$this->assertCount(2, $detail['attempts']);
		$this->assertSame(['kind' => 'password_login', 'label' => 'Failed password login', 'uid' => null], array_diff_key($detail['attempts'][0], ['createdAt' => 0]));
		$this->assertSame('ids_alice', $detail['attempts'][1]['uid']);
		$this->assertSame(14, $detail['explanation']['facts']['failures']);
		$this->assertSame([$ban->getId()], array_column($detail['bans'], 'id'));
		$this->assertNotSame('', $detail['text']);
		$this->assertStringNotContainsString(self::SECRET_FINGERPRINT, $json);
		$this->assertStringNotContainsString(self::SECRET_NAME_HMAC, $json);
		$this->assertStringNotContainsString('pw_fp', $json);
	}

	public function testAttemptsAreNotShownForOlderDetections(): void {
		$detection = $this->insertDetection(ManualBlock::ID, 'medium', true, '203.0.113.7', null, createdAt: time() - 7200);
		$detail = $this->controller->detection((int)$detection->getId())->getData();
		$this->assertFalse($detail['attemptsAvailable']);
		$this->assertSame([], $detail['attempts']);
	}

	public function testDetectionListsNeverContainSecrets(): void {
		$this->insertDetection(ManualBlock::ID, 'medium', true, '203.0.113.7', null, facts: ['pw_fp' => self::SECRET_FINGERPRINT]);
		$json = (string)json_encode([
			$this->controller->detections()->getData(),
			$this->controller->lookup('203.0.113.7')->getData(),
			$this->controller->status()->getData(),
		]);
		$this->assertStringNotContainsString(self::SECRET_FINGERPRINT, $json);
	}

	public function testLookupByReferenceInAnyForm(): void {
		$detection = $this->insertDetection(ManualBlock::ID, 'medium', true, '203.0.113.7', null);
		$ban = $this->banService->banManually('203.0.113.7', 1, 'test', null);
		$ban->setDetectionId((int)$detection->getId());
		$this->bans->update($ban);
		$reference = $ban->getDisplayReference();

		foreach ([$reference, strtolower($reference), str_replace('-', '', $reference), ' ' . strtolower(str_replace('-', ' ', $reference)) . ' '] as $query) {
			$result = $this->controller->lookup($query)->getData();
			$this->assertSame('reference', $result['kind'], $query);
			$this->assertSame($ban->getId(), $result['bans'][0]['id']);
			$this->assertSame($detection->getId(), $result['detections'][0]['id']);
		}
	}

	public function testLookupByAddressShowsCoveringBlocksAndRecentDetections(): void {
		$this->banService->banManually('203.0.113.0/24', 1, 'test', null);
		$this->insertDetection(ManualBlock::ID, 'medium', true, '203.0.113.7', null);
		$this->insertDetection(ManualBlock::ID, 'medium', true, '203.0.113.7', null, createdAt: time() - 40 * 86400);

		$result = $this->controller->lookup('203.0.113.7')->getData();

		$this->assertSame('address', $result['kind']);
		$this->assertSame(['203.0.113.0/24'], array_column($result['bans'], 'cidr'));
		$this->assertCount(1, $result['detections']);
		$this->assertSame([], $this->controller->lookup('198.51.100.1')->getData()['bans']);
	}

	public function testLookupByUser(): void {
		$this->insertDetection(SharedAddress::ID, 'high', true, null, 'ids_alice');
		$result = $this->controller->lookup('ids_alice')->getData();
		$this->assertSame('user', $result['kind']);
		$this->assertSame(['uid' => 'ids_alice', 'displayName' => 'Alice Liddell'], $result['user']);
		$this->assertCount(1, $result['detections']);

		$this->assertSame('none', $this->controller->lookup('nobody-here')->getData()['kind']);
		$this->assertSame('none', $this->controller->lookup('ZZZZ-ZZZZ')->getData()['kind']);
		$this->assertSame('none', $this->controller->lookup('')->getData()['kind']);
	}

	public function testDailyStatsFillEveryDay(): void {
		$this->insertDetection(ManualBlock::ID, 'medium', true, '203.0.113.7', null);
		$this->insertDetection(ManualBlock::ID, 'medium', false, '203.0.113.8', null);
		$this->insertDetection(SharedAddress::ID, 'high', true, '203.0.113.9', null, createdAt: time() - 2 * 86400);
		$this->insertDetection(ManualBlock::ID, 'medium', true, '203.0.113.7', null, createdAt: time() - 40 * 86400);

		$days = $this->controller->dailyStats(30)->getData()['days'];

		$this->assertCount(30, $days);
		$today = end($days);
		$this->assertSame(['enforced' => 1, 'observed' => 1], array_intersect_key($today, ['enforced' => 0, 'observed' => 0]));
		$this->assertSame(['internal' => ['enforced' => 1, 'observed' => 1]], $today['categories']);
		$this->assertSame(1, $days[27]['enforced']);
		$this->assertSame(3, array_sum(array_map(static fn (array $d): int => $d['enforced'] + $d['observed'], $days)));
		// Consecutive local days.
		$this->assertSame(86400, $days[1]['start'] - $days[0]['start']);
		$this->assertCount(90, $this->controller->dailyStats(500)->getData()['days']);
	}

	public function testBanListAndLifting(): void {
		$active = $this->banService->banManually('203.0.113.7', 1, 'test', 'first');
		$this->banService->banManually('203.0.113.8', 1, 'test', null);
		$ended = $this->banService->banManually('203.0.113.9', 1, 'test', null);
		$this->banService->lift($ended, 'test', 'done');

		$list = $this->controller->bans()->getData();
		$this->assertSame(2, $list['activeCount']);
		$this->assertCount(2, $list['bans']);
		$this->assertFalse($list['hasMore']);
		$this->assertTrue($list['bans'][0]['active']);
		$this->assertSame('Blocked by an administrator', $list['bans'][0]['checkName']);

		$this->assertCount(3, $this->controller->bans(true)->getData()['bans']);
		$page = $this->controller->bans(true, 2)->getData();
		$this->assertCount(2, $page['bans']);
		$this->assertTrue($page['hasMore']);

		$lifted = $this->controller->liftBan((int)$active->getId(), 'false alarm')->getData();
		$this->assertFalse($lifted['active']);
		$this->assertSame('ids_admin', $lifted['liftedBy']);
		$this->assertSame('false alarm', $lifted['liftNote']);
		$this->assertSame(1, $this->controller->bans()->getData()['activeCount']);
	}

	public function testManualBlockThroughTheApi(): void {
		$response = $this->controller->addBan('2001:db8:1:2::7', 2, null, 'scanner');
		$this->assertSame(Http::STATUS_OK, $response->getStatus());
		$ban = $response->getData();
		$this->assertSame('2001:db8:1:2::/64', $ban['cidr']);
		$this->assertSame(2, $ban['level']);
		$this->assertSame('ids_admin', $ban['createdBy']);
		$this->assertMatchesRegularExpression('/^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/', $ban['reference']);
	}

	public function testSettingsRoundTripExportAndReset(): void {
		$response = $this->controller->updateSettings([GlobalSettings::BAN_DURATION_1 => '2h', GlobalSettings::BAN_NET_AFTER => 4]);
		$this->assertSame(Http::STATUS_OK, $response->getStatus());
		$settings = array_column($response->getData()['settings'], 'value', 'name');
		$this->assertSame(7200, $settings[GlobalSettings::BAN_DURATION_1]);
		$this->assertArrayNotHasKey(GlobalSettings::BAN_VERSION, $settings);
		$this->assertArrayNotHasKey(GlobalSettings::LEARNING_UNTIL, $settings);
		$this->assertArrayHasKey('escalation', $response->getData()['templates']);

		$export = $this->controller->exportSettings()->getData();
		$this->assertSame(7200, $export['settings'][GlobalSettings::BAN_DURATION_1]);
		$this->assertArrayNotHasKey(GlobalSettings::INSTALLED_AT, $export['settings']);

		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::LEARNING_UNTIL, time() + 86400);
		$this->controller->resetSettings();
		$settings = Server::get(Settings::class);
		$this->assertSame(14400, $settings->getInt(GlobalSettings::BAN_DURATION_1));
		$this->assertSame(3, $settings->getInt(GlobalSettings::BAN_NET_AFTER));
		// Learning mode is not a setting and survives the reset.
		$this->assertTrue($settings->isLearning());
	}

	public function testLearningModeThroughTheApi(): void {
		$learning = $this->controller->updateLearning('start', 3)->getData();
		$this->assertTrue($learning['active']);
		$this->assertSame(3, $learning['daysLeft']);
		$this->assertFalse($this->controller->updateLearning('stop')->getData()['active']);
	}

	public function testScrubKeepsOrdinaryFacts(): void {
		$this->assertSame(
			['failures' => 14, 'targets' => ['alice', 'bob'], 'path' => '/.env', 'tokenIds' => [5], 'list' => ['kept']],
			DetectionPresenter::scrub(['failures' => 14, 'targets' => ['alice', 'bob'], 'path' => '/.env', 'secret' => 'x', 'tokenIds' => [5], 'list' => [self::SECRET_FINGERPRINT, 'kept']]),
		);
	}

	/**
	 * @param array<string, mixed> $facts
	 * @param list<array{type: string, enforced: bool}> $actions
	 */
	private function insertDetection(string $checkId, string $severity, bool $enforced, ?string $ip, ?string $uid, ?int $createdAt = null, array $facts = [], array $actions = []): Detection {
		$createdAt ??= time();
		$detection = new Detection();
		$detection->setCheckId($checkId);
		$detection->setSeverity($severity);
		$detection->setEnforced($enforced);
		$detection->setIp($ip);
		$detection->setNetKey($ip === null ? null : preg_replace('/\.\d+$/', '.0/24', $ip));
		$detection->setUid($uid);
		$detection->setExplanationData(['v' => 1, 'check' => $checkId, 'mode' => ['configured' => 'protect', 'effective' => $enforced ? 'protect' : 'observe', 'reason' => null], 'facts' => $facts]);
		$detection->setActionList($actions);
		$detection->setCreatedAt($createdAt);
		$detection->setLastSeenAt($createdAt);
		$detection->setHits(1);
		return $this->detections->insert($detection);
	}
}
