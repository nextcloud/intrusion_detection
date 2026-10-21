<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\DB\ConnectionAdapter;
use OCA\IntrusionDetection\Admin\DetectionPresenter;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\AccountUnderAttack;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffing;
use OCA\IntrusionDetection\Check\Checks\PasswordSpraying;
use OCA\IntrusionDetection\Check\Checks\ResetProbing;
use OCA\IntrusionDetection\Check\Checks\ResetProbingDetector;
use OCA\IntrusionDetection\Check\Checks\ShareBruteforce;
use OCA\IntrusionDetection\Check\Checks\ShareBruteforceDetector;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Detection\AttemptRecord;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\Risk\RiskAssessment;
use OCA\IntrusionDetection\Risk\RiskScorer;
use OCP\IDBConnection;
use OCP\IL10N;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * Where the address risk score changes what the checks do (concept section
 * 10.18): the count limits of the login-failure checks, with the
 * explanation that says so, and the score kept with every new detection.
 * The `risk_high` step-up reason is covered with the risky networks.
 */
#[Group('DB')]
class RiskLimitsTest extends LoginFailureTestCase {
	private IL10N $l;

	protected function setUp(): void {
		parent::setUp();
		// The tests' memory cache lives as long as the process: start from an empty one.
		(new \ReflectionProperty(RiskScorer::class, 'cacheInitialised'))->setValue(Server::get(RiskScorer::class), false);
		$this->settings->setGlobal(GlobalSettings::RISK_ENABLED, true);
		$this->l = Server::get(IFactory::class)->get(Application::APP_ID, 'en');
	}

	public function testCredentialStuffingFromAnAttackToolMeetsLowerLimits(): void {
		for ($i = 1; $i <= 5; $i++) {
			$this->failLogin('198.51.100.7', 'user' . $i);
		}
		$detections = $this->detectionsOf(CredentialStuffing::ID);
		$this->assertCount(1, $detections, '5 failures for 5 accounts are enough for this address');
		$facts = $detections[0]->getExplanationData()['facts'];
		$this->assertSame(['min_failures' => ['plain' => 10, 'effective' => 5], 'min_names' => ['plain' => 5, 'effective' => 3]], $facts['loweredLimits']);
		$this->assertSame(3, $facts['risk']['score']);

		$happened = Server::get(NarrativeBuilder::class)->build($detections[0], $this->l)->happened;
		$this->assertContains(
			'The limits for this address were lower, because its risk score was 3 (attack tool "curl" +2, 5 failed logins in the last hour +1): Failed logins: 5 instead of 10; Different accounts: 3 instead of 5.',
			$happened,
		);

		$risk = Server::get(DetectionPresenter::class)->detail($detections[0], $this->l)['risk'];
		$this->assertNotNull($risk);
		$this->assertSame(3, $risk['score']);
		$this->assertSame('elevated', $risk['tier']);
		$this->assertSame('Elevated', $risk['tierLabel']);
		$this->assertSame([
			['fact' => RiskAssessment::FACT_ATTACK_TOOL, 'label' => 'attack tool "curl"', 'points' => 2],
			['fact' => RiskAssessment::FACT_FAILURES, 'label' => '5 failed logins in the last hour', 'points' => 1],
		], $risk['parts']);
		$this->assertSame([
			['param' => 'min_failures', 'label' => 'Failed logins', 'plain' => 10, 'effective' => 5],
			['param' => 'min_names', 'label' => 'Different accounts', 'plain' => 5, 'effective' => 3],
		], $risk['lowered']);
	}

	public function testABrowserMeetsThePlainLimits(): void {
		$this->userAgent = 'Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0';
		for ($i = 1; $i <= 9; $i++) {
			$this->failLogin('198.51.100.7', 'user' . $i);
		}
		$this->assertSame([], $this->detectionsOf(CredentialStuffing::ID), '9 failures earn 1 point: limits as configured');
		// A minute later the stored facts are read again.
		(new \ReflectionProperty(RiskScorer::class, 'cacheInitialised'))->setValue(Server::get(RiskScorer::class), false);
		$this->failLogin('198.51.100.7', 'user10');
		$detections = $this->detectionsOf(CredentialStuffing::ID);
		$this->assertCount(1, $detections);
		$facts = $detections[0]->getExplanationData()['facts'];
		$this->assertArrayNotHasKey('loweredLimits', $facts);
		$this->assertSame(2, $facts['risk']['score'], 'The score is kept with the detection');
		$this->assertContains(
			'The risk score of the address was 2 (10 failed logins in the last hour +2).',
			Server::get(NarrativeBuilder::class)->build($detections[0], $this->l)->happened,
		);
	}

	public function testWithTheScoreOffThePlainLimitsApply(): void {
		$this->settings->setGlobal(GlobalSettings::RISK_ENABLED, false);
		for ($i = 1; $i <= 9; $i++) {
			$this->failLogin('198.51.100.7', 'user' . $i);
		}
		$this->assertSame([], $this->detectionsOf(CredentialStuffing::ID));
		$this->assertSame([], array_filter(array_column($this->allRows('ids_flags'), 'flag_key'), static fn (string $key): bool => str_starts_with($key, 'tool:')), 'The attack tool is not even remembered');
		$this->failLogin('198.51.100.7', 'user10');
		$this->assertArrayNotHasKey('risk', $this->detectionsOf(CredentialStuffing::ID)[0]->getExplanationData()['facts']);
	}

	public function testPasswordSprayingFromARiskyAddressNeedsFewerAccounts(): void {
		foreach (['198.51.100.21' => 'anna', '198.51.100.22' => 'bert', '198.51.100.23' => 'cleo'] as $ip => $name) {
			$this->failLogin($ip, $name, 'Summer-2026!');
		}
		$detections = $this->detectionsOf(PasswordSpraying::ID);
		$this->assertCount(1, $detections, 'Three accounts instead of five');
		$this->assertSame(['min_names' => ['plain' => 5, 'effective' => 3]], $detections[0]->getExplanationData()['facts']['loweredLimits']);
		$this->assertContains(
			'The limit for this address was 3 instead of 5, because its risk score was 2 (attack tool "curl" +2).',
			Server::get(NarrativeBuilder::class)->build($detections[0], $this->l)->happened,
		);
	}

	public function testOneAccountAttackedFromRiskyAddressesIsNoticedSooner(): void {
		$this->user('victim');
		foreach (['198.51.100.31', '198.51.100.31', '198.51.100.32', '198.51.100.32'] as $ip) {
			$this->failLogin($ip, 'victim');
		}
		$this->assertSame([], $this->detectionsOf(AccountUnderAttack::ID));
		$this->failLogin('198.51.100.33', 'victim');
		$detections = $this->detectionsOf(AccountUnderAttack::ID);
		$this->assertCount(1, $detections, '5 failures from 3 addresses instead of 10 from 5');
		$this->assertSame(['plain' => 5, 'effective' => 3], $detections[0]->getExplanationData()['facts']['loweredLimits']['min_sources']);
	}

	public function testShareTokenGuessingFromAMarkedAddressMeetsALowerLimit(): void {
		$source = SourceKey::fromIp('198.51.100.41');
		Server::get(FlaggedSources::class)->flagSource($source, FlaggedSources::REASON_ATTACK);
		for ($i = 1; $i <= 5; $i++) {
			$this->attempts->insert(AttemptKind::UnknownShareToken, $source->ipKey, $source->netKey, bin2hex(Server::get(Fingerprinter::class)->shareToken('guessed' . $i)), null, null, null, time());
		}
		Server::get(ShareBruteforceDetector::class)->unknownToken(new AttemptRecord(AttemptKind::UnknownShareToken, $source, null, null, null, null, [], time(), true), null);
		$detections = $this->detectionsOf(ShareBruteforce::ID);
		$this->assertCount(1, $detections);
		$this->assertSame(['token_min' => ['plain' => 10, 'effective' => 5]], $detections[0]->getExplanationData()['facts']['loweredLimits']);
	}

	public function testResetEnumerationFromAMarkedAddressMeetsALowerLimit(): void {
		$source = SourceKey::fromIp('198.51.100.51');
		Server::get(FlaggedSources::class)->flagSource($source, FlaggedSources::REASON_ATTACK);
		foreach (['a@example.com', 'b@example.com', 'c@example.com'] as $input) {
			$this->attempts->insert(AttemptKind::PasswordReset, $source->ipKey, $source->netKey, bin2hex(Server::get(Fingerprinter::class)->name($input)), null, null, null, time());
		}
		Server::get(ResetProbingDetector::class)->detect(new AttemptRecord(AttemptKind::PasswordReset, $source, null, null, null, null, [], time(), true), null);
		$detections = $this->detectionsOf(ResetProbing::ID);
		$this->assertCount(1, $detections);
		$this->assertSame(['enum_min_inputs' => ['plain' => 5, 'effective' => 3]], $detections[0]->getExplanationData()['facts']['loweredLimits']);
	}

	public function testAnOrdinaryFailedLoginCostsNoExtraQuery(): void {
		$this->userAgent = 'Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0';
		// The first failed login of the process also looks the account up; it is not compared.
		$this->failLogin('198.51.100.60', 'someone');
		$counts = [];
		foreach ([false, true, false, true] as $i => $on) {
			$this->settings->setGlobal(GlobalSettings::RISK_ENABLED, $on);
			$counts[] = $this->queriesFor(fn () => $this->failLogin('198.51.100.7' . $i, 'someone'));
		}
		$this->assertSame([$counts[0], $counts[0], $counts[0], $counts[0]], $counts, 'The score is only computed close to a limit');
	}

	/**
	 * @return list<Detection>
	 */
	protected function detectionsOf(string $checkId): array {
		return parent::detectionsOf($checkId);
	}

	private function queriesFor(\Closure $action): int {
		$connection = Server::get(IDBConnection::class);
		$this->assertInstanceOf(ConnectionAdapter::class, $connection);
		$before = $connection->getInner()->getStats()['executed'];
		$action();
		return $connection->getInner()->getStats()['executed'] - $before;
	}
}
