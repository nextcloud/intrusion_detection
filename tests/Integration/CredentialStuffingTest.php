<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\AccountUnderAttack;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffing;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffingDetector;
use OCA\IntrusionDetection\Check\Checks\PasswordSpraying;
use OCA\IntrusionDetection\Check\Checks\SharedAddress;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Db\FlagMapper;
use OCA\IntrusionDetection\Db\LoginMapper;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Net\SourceKey;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

#[Group('DB')]
class CredentialStuffingTest extends LoginFailureTestCase {
	private BanMapper $bans;

	protected function setUp(): void {
		parent::setUp();
		$this->bans = Server::get(BanMapper::class);
		// Only the check under test runs, so other checks cannot interfere.
		$this->settings->setMode(PasswordSpraying::ID, Mode::Off);
		$this->settings->setMode(AccountUnderAttack::ID, Mode::Off);
	}

	public function testOneAddressTryingManyAccountsIsBlockedAtTheThreshold(): void {
		for ($i = 1; $i <= 9; $i++) {
			$this->failLogin('198.51.100.7', 'user' . ($i % 5));
		}
		$this->assertSame([], $this->detectionsOf(CredentialStuffing::ID), '9 failures are below the limit of 10');

		$this->failLogin('198.51.100.7', 'user0');
		$detections = $this->detectionsOf(CredentialStuffing::ID);
		$this->assertCount(1, $detections);
		$detection = $detections[0];
		$this->assertTrue($detection->isEnforced());
		$this->assertSame('198.51.100.7', $detection->getIp());
		$facts = $detection->getExplanationData()['facts'];
		$this->assertSame(CredentialStuffing::RULE_SOURCE, $facts['rule']);
		$this->assertSame(10, $facts['failures']);
		$this->assertSame(5, $facts['names']);
		$this->assertSame(10, $detection->getExplanationData()['thresholds']['min_failures']);

		$this->assertCount(1, $this->bans->findActiveForKeys(['198.51.100.7'], time()));
		$this->assertNotSame([], Server::get(FlagMapper::class)->active(['ip:198.51.100.7'], time()));
		$types = array_column($detection->getActionList(), 'enforced', 'type');
		$this->assertTrue($types['ban']);
		$this->assertTrue($types['flag_source']);
	}

	public function testDistinctNamesAreCounted(): void {
		for ($i = 1; $i <= 12; $i++) {
			$this->failLogin('198.51.100.7', 'user' . ($i % 4));
		}
		$this->assertSame([], $this->detectionsOf(CredentialStuffing::ID), '12 failures for 4 names are below 5 names');
		$this->assertSame(12, $this->rows('ids_attempts'));
	}

	public function testRepeatedHitsMergeIntoOneDetection(): void {
		$this->settings->setMode(CredentialStuffing::ID, Mode::Observe);
		for ($i = 1; $i <= 14; $i++) {
			$this->failLogin('198.51.100.7', 'user' . $i);
		}
		$detections = $this->detectionsOf(CredentialStuffing::ID);
		$this->assertCount(1, $detections);
		$this->assertSame(5, $detections[0]->getHits());
	}

	public function testAttemptsOutsideTheWindowDoNotCount(): void {
		for ($i = 1; $i <= 9; $i++) {
			$this->storeAttempt('198.51.100.7', 'old' . $i, at: time() - 700);
		}
		$this->failLogin('198.51.100.7', 'new');
		$this->assertSame([], $this->detectionsOf(CredentialStuffing::ID));
	}

	public function testANetworkIsHeldToThreeTimesTheNumbers(): void {
		// 30 addresses of one /24, one failure each, 15 names: no address alone reaches the limit.
		for ($i = 1; $i <= 29; $i++) {
			$this->storeAttempt('203.0.113.' . $i, 'name' . ($i % 15));
		}
		$this->failLogin('203.0.113.30', 'name0');
		$detections = $this->detectionsOf(CredentialStuffing::ID);
		$this->assertCount(1, $detections);
		$facts = $detections[0]->getExplanationData()['facts'];
		$this->assertSame(CredentialStuffing::RULE_NETWORK, $facts['rule']);
		$this->assertSame('203.0.113.0/24', $facts['net']);
		$this->assertSame(30, $facts['sources']);
		// Every address of the network that took part is blocked, and with that the network.
		$this->assertCount(1, $this->bans->findActiveForKeys(['203.0.113.0/24'], time()));
		$this->assertCount(1, $this->bans->findActiveForKeys(['203.0.113.17'], time()));
	}

	public function testANetworkBelowThreeTimesTheNumbersDoesNotFire(): void {
		for ($i = 1; $i <= 28; $i++) {
			$this->storeAttempt('203.0.113.' . $i, 'name' . ($i % 15));
		}
		$this->failLogin('203.0.113.29', 'name0');
		$this->assertSame([], $this->detectionsOf(CredentialStuffing::ID), '29 failures are below 3 × 10');
	}

	public function testIpv6AddressesOfOneSlash64AreOneSource(): void {
		for ($i = 1; $i <= 10; $i++) {
			$this->failLogin('2001:db8:1:2::' . dechex($i), 'user' . ($i % 5));
		}
		$detections = $this->detectionsOf(CredentialStuffing::ID);
		$this->assertCount(1, $detections);
		$this->assertSame(CredentialStuffing::RULE_SOURCE, $detections[0]->getExplanationData()['facts']['rule']);
		$this->assertCount(1, $this->bans->findActiveForKeys(['2001:db8:1:2::/64'], time()));
	}

	public function testOffRecordsNothing(): void {
		$this->settings->setMode(CredentialStuffing::ID, Mode::Off);
		for ($i = 1; $i <= 12; $i++) {
			$this->failLogin('198.51.100.7', 'user' . $i);
		}
		$this->assertSame(0, $this->rows('ids_attempts'), 'With every login check off, no attempt is stored');
		$this->assertSame(0, $this->rows('ids_detections'));
		$this->assertSame(0, $this->rows('ids_bans'));
	}

	public function testObserveRecordsWhatWouldHaveHappened(): void {
		$this->settings->setMode(CredentialStuffing::ID, Mode::Observe);
		for ($i = 1; $i <= 10; $i++) {
			$this->failLogin('198.51.100.7', 'user' . $i);
		}
		$detection = $this->detectionsOf(CredentialStuffing::ID)[0];
		$this->assertFalse($detection->isEnforced());
		foreach ($detection->getActionList() as $action) {
			$this->assertFalse($action['enforced']);
		}
		$this->assertSame(0, $this->rows('ids_bans'));
		$this->assertSame(0, $this->rows('ids_flags'));
	}

	public function testLearningModeObservesAndTheNarrativeSaysSo(): void {
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::LEARNING_UNTIL, time() + 86400);
		for ($i = 1; $i <= 10; $i++) {
			$this->failLogin('198.51.100.7', 'user' . $i);
		}
		$detection = $this->detectionsOf(CredentialStuffing::ID)[0];
		$this->assertFalse($detection->isEnforced());
		$this->assertSame(0, $this->rows('ids_bans'));

		$narrative = Server::get(NarrativeBuilder::class)->build($detection, Server::get(IFactory::class)->get(Application::APP_ID, 'en'));
		$this->assertStringContainsString('failed to log in 10 times, trying 10 different accounts', $narrative->happened[0]);
		$this->assertStringContainsString('The limit at that time was 10 failures for 5 accounts within 10 minutes', implode(' ', $narrative->happened));
		$this->assertStringContainsString('learning mode', (string)$narrative->observedBecause);
	}

	public function testTheNarrativeKeepsTheThresholdsOfItsTime(): void {
		for ($i = 1; $i <= 10; $i++) {
			$this->failLogin('198.51.100.7', 'user' . $i);
		}
		$this->settings->setParam(CredentialStuffing::ID, 'min_failures', 50);
		$detection = $this->detectionsOf(CredentialStuffing::ID)[0];
		$narrative = Server::get(NarrativeBuilder::class)->build($detection, Server::get(IFactory::class)->get(Application::APP_ID, 'en'));
		$this->assertStringContainsString('10 failures for 5 accounts', implode(' ', $narrative->happened));
	}

	public function testADistributedAttackIsRecordedOnceAndBlocksAddressesThatFailRepeatedly(): void {
		$this->settings->setParam(CredentialStuffing::ID, 'min_failures', 1000);
		// 100 failures from 25 addresses for 25 names, spread over the last minutes.
		for ($i = 0; $i < 99; $i++) {
			$this->storeAttempt('192.0.2.' . ($i % 25 + 1), 'victim' . ($i % 25), at: time() - 120);
		}
		$this->failLogin('192.0.2.1', 'victim99');
		$distributed = array_values(array_filter(
			$this->detectionsOf(CredentialStuffing::ID),
			static fn ($d): bool => ($d->getExplanationData()['facts']['distributed'] ?? false) === true,
		));
		$this->assertCount(1, $distributed);
		$this->assertNull($distributed[0]->getIp());
		$this->assertGreaterThan(time(), $this->settings->getInt(GlobalSettings::CS_DISTRIBUTED_UNTIL));
		// 192.0.2.1 failed 5 times for 2 or more names: blocked, with the distributed detection as reason.
		$ban = $this->bans->findActiveForKeys(['192.0.2.1'], time())[0] ?? null;
		$this->assertNotNull($ban);
		$this->assertSame($distributed[0]->getId(), $ban->getDetectionId());

		// More failures within 30 minutes add no second distributed detection.
		$this->failLogin('192.0.2.2', 'victim100');
		$this->assertCount(1, array_filter(
			$this->detectionsOf(CredentialStuffing::ID),
			static fn ($d): bool => ($d->getExplanationData()['facts']['distributed'] ?? false) === true,
		));
	}

	public function testDuringADistributedAttackEveryFailingAddressIsFlaggedButOnlyRepeatOffendersBlocked(): void {
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::CS_DISTRIBUTED_UNTIL, time() + 300);
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::CS_DISTRIBUTED_DETECTED_AT, time());
		$this->failLogin('192.0.2.200', 'someone');
		$this->assertNotSame([], Server::get(FlagMapper::class)->active(['ip:192.0.2.200'], time()));
		$this->assertSame([], $this->bans->findActiveForKeys(['192.0.2.200'], time()), 'One failure is not enough for a block');

		$this->failLogin('192.0.2.200', 'someone');
		$this->assertSame([], $this->bans->findActiveForKeys(['192.0.2.200'], time()), 'Two failures for one name are not enough');
		$this->failLogin('192.0.2.200', 'someone-else');
		$this->assertCount(1, $this->bans->findActiveForKeys(['192.0.2.200'], time()), '3 failures for 2 names are');
	}

	public function testASharedAddressInADistributedAttackIsReportedInsteadOfBlocked(): void {
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::CS_DISTRIBUTED_UNTIL, time() + 300);
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::CS_DISTRIBUTED_DETECTED_AT, time());
		$source = SourceKey::fromIp('192.0.2.210');
		foreach (['alice', 'bob', 'carol', 'dave', 'erin'] as $uid) {
			Server::get(LoginMapper::class)->record($source->ipKey, $source->netKey, $uid, intdiv(time(), 3600));
		}
		foreach (['someone', 'someone', 'someone-else'] as $name) {
			$this->failLogin('192.0.2.210', $name);
		}
		$this->assertSame([], $this->bans->findActiveForKeys(['192.0.2.210'], time()), 'Many people log in from it');
		$shared = $this->detectionsOf(SharedAddress::ID);
		$this->assertCount(1, $shared);
		$this->assertSame(CredentialStuffing::ID, $shared[0]->getExplanationData()['facts']['wantedBy']);
	}

	public function testAfterADistributedAttackFailingAddressesStayFlaggedForAnHour(): void {
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::CS_DISTRIBUTED_UNTIL, time() - 600);
		$this->failLogin('192.0.2.201', 'a');
		$this->failLogin('192.0.2.201', 'b');
		$this->failLogin('192.0.2.201', 'c');
		$this->assertNotSame([], Server::get(FlagMapper::class)->active(['ip:192.0.2.201'], time()));
		$this->assertSame([], $this->bans->findActiveForKeys(['192.0.2.201'], time()), 'Blocking ends with the attack');
	}

	public function testTheDistributedRuleOnlyObservesInObserveMode(): void {
		$this->settings->setMode(CredentialStuffing::ID, Mode::Observe);
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::CS_DISTRIBUTED_UNTIL, time() + 300);
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::CS_DISTRIBUTED_DETECTED_AT, time());
		for ($i = 0; $i < 3; $i++) {
			$this->failLogin('192.0.2.202', 'n' . $i);
		}
		$this->assertSame(0, $this->rows('ids_flags'));
		$this->assertSame(0, $this->rows('ids_bans'));
	}

	public function testWithoutAMemoryCacheTheInstanceIsEvaluatedOnceEvery30Seconds(): void {
		$cacheFactory = $this->createMock(\OCP\ICacheFactory::class);
		$cacheFactory->method('isLocalCacheAvailable')->willReturn(false);
		$detector = new CredentialStuffingDetector(
			$this->settings,
			$this->attempts,
			Server::get(\OCA\IntrusionDetection\Response\ResponseEngine::class),
			Server::get(\OCA\IntrusionDetection\Response\FlaggedSources::class),
			Server::get(\OCA\IntrusionDetection\Response\BanService::class),
			Server::get(\OCA\IntrusionDetection\Net\RemoteAddressResolver::class),
			$cacheFactory,
			Server::get(\OCA\IntrusionDetection\Risk\RiskScorer::class),
		);
		$recorder = Server::get(\OCA\IntrusionDetection\Detection\AttemptRecorder::class);
		$fail = static fn (string $ip, string $name) => $detector->detect($recorder->record(AttemptKind::PasswordLogin, \OCA\IntrusionDetection\Net\SourceKey::fromIp($ip), $name, null, null, 'wrong'), null);
		$this->settings->setParam(CredentialStuffing::ID, 'min_failures', 1000);

		$fail('192.0.2.30', 'first');
		$evaluatedAt = $this->settings->getInt(GlobalSettings::CS_EVALUATED_AT);
		$this->assertGreaterThanOrEqual(time() - 5, $evaluatedAt);

		// A distributed attack starts now; it is noticed at the next evaluation, not at once.
		for ($i = 0; $i < 99; $i++) {
			$this->storeAttempt('192.0.2.' . ($i % 25 + 1), 'victim' . ($i % 25), at: time() - 60);
		}
		$db = Server::get(\OCP\IDBConnection::class);
		$queries = $db->getInner()->getStats()['executed'];
		$fail('192.0.2.31', 'second');
		$withoutEvaluation = $db->getInner()->getStats()['executed'] - $queries;
		$this->assertSame($evaluatedAt, $this->settings->getInt(GlobalSettings::CS_EVALUATED_AT));
		$this->assertSame(0, $this->settings->getInt(GlobalSettings::CS_DISTRIBUTED_UNTIL), 'not evaluated within 30 seconds');

		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::CS_EVALUATED_AT, time() - CredentialStuffingDetector::EVALUATE_EVERY);
		$queries = $db->getInner()->getStats()['executed'];
		$fail('192.0.2.32', 'third');
		$this->assertGreaterThan($withoutEvaluation, $db->getInner()->getStats()['executed'] - $queries, 'the evaluation costs queries of its own');
		$this->assertGreaterThan(time(), $this->settings->getInt(GlobalSettings::CS_DISTRIBUTED_UNTIL));
	}
}
