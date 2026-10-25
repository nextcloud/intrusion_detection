<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Admin\CheckNames;
use OCA\IntrusionDetection\Admin\LearningRecap;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Check\Checks\InjectionProbe\InjectionProbe;
use OCA\IntrusionDetection\Check\Checks\TrapUrl\TrapUrl;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Config\UserKeys;
use OCA\IntrusionDetection\Db\StatsMapper;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Learning\LearningService;
use OCA\IntrusionDetection\LoginHistory\Db\LoginHistoryMapper;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCA\IntrusionDetection\State\AppState;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Config\IUserConfig;
use OCP\IL10N;
use OCP\IUserManager;
use OCP\L10N\IFactory;
use OCP\Notification\IManager as INotificationManager;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

#[Group('DB')]
class LearningRecapTest extends IntegrationTestCase {
	use CreatesAccounts;

	private const WEEK = 7 * 86400;

	private int $now;
	private int $installedAt;
	private LearningService $learning;
	private LearningRecap $recap;
	private IL10N $l;

	protected function setUp(): void {
		parent::setUp();
		$this->now = time();
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturnCallback(fn (): int => $this->now);
		$this->learning = new LearningService($this->appSettings(), $this->settingsEditor(), $time, Server::get(AuditLogger::class), Server::get(INotificationManager::class), Server::get(AppState::class));
		$this->recap = new LearningRecap(
			$this->learning,
			Server::get(StatsMapper::class),
			Server::get(LoginHistory::class),
			Server::get(CheckNames::class),
			$this->appSettings(),
			Server::get(AppState::class),
			Server::get(IUserConfig::class),
			Server::get(IUserManager::class),
			$time,
			Server::get(Caches::class),
		);
		$this->l = Server::get(IFactory::class)->get(Application::APP_ID, 'en');

		// The app was installed a moment ago and learns for its first week.
		$this->installedAt = $this->now - 60;
		Server::get(AppState::class)->setInt(AppState::INSTALLED_AT, $this->installedAt);
		$this->now = $this->installedAt;
		$this->learning->startAtInstall($this->installedAt);
		$this->now = time();
	}

	protected function tearDown(): void {
		Server::get(IUserConfig::class)->deleteUserConfig('alice', Application::APP_ID, UserKeys::LEARNING_RECAP_CLOSED);
		$this->deleteAccounts();
		parent::tearDown();
	}

	public function testThereIsNoRecapWhileLearning(): void {
		$this->assertTrue($this->learning->isActive());
		$this->assertNull($this->recap->forAdmin('admin', $this->l));
	}

	public function testThereIsNoRecapForAnInstanceWhoseLearningEndedBeforeItWasRecorded(): void {
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::LEARNING_UNTIL, 0);
		$this->assertFalse($this->learning->isActive());
		$this->assertNull($this->learning->lastPeriod());
		$this->assertNull($this->recap->forAdmin('admin', $this->l));
	}

	public function testTheRecapOfTheFirstWeek(): void {
		$engine = Server::get(ResponseEngine::class);
		foreach (['198.51.100.7', '198.51.100.7', '198.51.100.8'] as $ip) {
			$engine->handle(new DetectionDraft(TrapUrl::ID, SourceKey::fromIp($ip)));
		}
		$engine->handle(new DetectionDraft(InjectionProbe::ID, SourceKey::fromIp('2001:db8:1:2::5')));
		// A check set to Observe on purpose would not block once learning is over.
		$engine->handle(new DetectionDraft(TrapUrl::ID, SourceKey::fromIp('198.51.100.9'), mode: new ModeState(Mode::Observe, Mode::Observe)));

		$mia = $this->account('mia');
		Server::get(IUserManager::class)->get($mia)?->setDisplayName('Mia Wagner');
		$ipv6 = $this->account('noah');
		$elsewhere = $this->account('olga');
		$refused = $this->account('piet');
		$this->login($mia, '198.51.100.7', time());
		$this->login($ipv6, '2001:db8:1:2::77', time(), 'confirmed');
		$this->login($elsewhere, '198.51.100.9', time());
		$this->login($refused, '198.51.100.8', time(), 'refused');

		// The hourly job notices a minute late that the week is over.
		$this->now = $this->installedAt + self::WEEK + 60;
		$this->assertTrue($this->learning->expireIfDue());
		$this->login($this->account('quinn'), '198.51.100.8', $this->now);

		$recap = $this->recap->forAdmin('admin', $this->l);
		$this->assertNotNull($recap);
		$this->assertSame([$this->installedAt, $this->installedAt + self::WEEK, 7, true], [$recap['startedAt'], $recap['endedAt'], $recap['days'], $recap['first']], 'It ended when it was planned to');
		$this->assertSame(5, $recap['attempts'], 'Every detection of an attack check, also of one set to Observe');
		$this->assertSame(4, $recap['addresses']);
		$this->assertSame(TrapUrl::ID, $recap['topAttack']['checkId'] ?? null);
		$this->assertSame(4, $recap['topAttack']['attempts'] ?? null);
		$this->assertSame('A visitor who is not logged in requests a path that no Nextcloud client ever requests.', $recap['topAttack']['summary'] ?? null);
		$this->assertSame(3, $recap['wouldHaveBlocked'], 'Not the address of the check set to Observe');
		$this->assertSame(2, $recap['ownPeople'], 'Accepted logins from would-be blocked addresses (an IPv6 /64) in the period only');
		$this->assertEqualsCanonicalizing([['uid' => $mia, 'displayName' => 'Mia Wagner'], ['uid' => $ipv6, 'displayName' => $ipv6]], $recap['accounts']);
		$this->assertTrue($recap['complete']);
	}

	public function testAQuietWeek(): void {
		$this->now = $this->installedAt + self::WEEK;
		$this->learning->expireIfDue();
		$recap = $this->recap->forAdmin('admin', $this->l);
		$this->assertNotNull($recap);
		$this->assertSame([0, 0, null, 0, 0, []], [$recap['attempts'], $recap['addresses'], $recap['topAttack'], $recap['wouldHaveBlocked'], $recap['ownPeople'], $recap['accounts']]);
	}

	public function testEachAdministratorClosesTheRecapForThemselves(): void {
		$this->now = $this->installedAt + self::WEEK;
		$this->learning->expireIfDue();
		$this->recap->close('alice');
		$this->assertNull($this->recap->forAdmin('alice', $this->l));
		$this->assertNotNull($this->recap->forAdmin('bob', $this->l));
	}

	public function testTheRecapIsShownForTwoWeeks(): void {
		$this->now = $this->installedAt + self::WEEK;
		$this->learning->expireIfDue();
		$this->now += LearningRecap::SHOW_DAYS * 86400;
		$this->assertNotNull($this->recap->forAdmin('admin', $this->l));
		$this->now++;
		$this->assertNull($this->recap->forAdmin('admin', $this->l));
	}

	public function testANewLearningPeriodReplacesTheRecap(): void {
		$this->now = $this->installedAt + self::WEEK;
		$this->learning->expireIfDue();
		$this->recap->close('alice');

		$this->now += 86400;
		$restarted = $this->now;
		$this->learning->start(3, 'alice');
		$this->assertNull($this->learning->lastPeriod());
		$this->assertNull($this->recap->forAdmin('bob', $this->l), 'Not while learning again');

		$this->now += 2 * 86400;
		$this->learning->stop('alice');
		$recap = $this->recap->forAdmin('alice', $this->l);
		$this->assertNotNull($recap, 'The new period has a recap of its own');
		$this->assertSame([$restarted, $this->now, 2, false], [$recap['startedAt'], $recap['endedAt'], $recap['days'], $recap['first']], 'Ended early, by an administrator');
	}

	public function testDetectionsOlderThanTheRetentionMakeTheRecapIncomplete(): void {
		$this->now = $this->installedAt + self::WEEK;
		$this->learning->expireIfDue();
		$this->now += 2 * 86400;
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::RETENTION_DETECTIONS_DAYS, 7);
		$this->assertFalse($this->recap->forAdmin('admin', $this->l)['complete'] ?? null);
	}

	private function login(string $uid, string $ip, int $at, ?string $stepUp = null): void {
		Server::get(LoginHistoryMapper::class)->insert($uid, $at, SourceKey::fromIp($ip), 'Mozilla/5.0', LoginHistory::METHOD_PASSWORD, false, LoginHistory::CONFIRMED_BY_NONE, $stepUp, null);
	}
}
