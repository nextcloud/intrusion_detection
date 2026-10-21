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
use OCA\IntrusionDetection\Check\Checks\PasswordSpraying;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

#[Group('DB')]
class PasswordSprayingTest extends LoginFailureTestCase {
	private const SPRAYED = 'Summer2026!';

	private BanMapper $bans;
	private FlaggedSources $flags;

	protected function setUp(): void {
		parent::setUp();
		$this->bans = Server::get(BanMapper::class);
		$this->flags = Server::get(FlaggedSources::class);
		$this->settings->setMode(CredentialStuffing::ID, Mode::Off);
		$this->settings->setMode(AccountUnderAttack::ID, Mode::Off);
	}

	public function testOnePasswordAgainstManyAccountsBlocksEverySourceAndFlagsThePassword(): void {
		for ($i = 1; $i <= 4; $i++) {
			$this->failLogin('198.51.100.' . $i, 'user' . $i, self::SPRAYED);
		}
		$this->assertSame([], $this->detectionsOf(PasswordSpraying::ID), '4 accounts are below the limit of 5');
		$this->assertFalse($this->isFlagged(self::SPRAYED));

		$this->failLogin('198.51.100.5', 'user5', self::SPRAYED);
		$detections = $this->detectionsOf(PasswordSpraying::ID);
		$this->assertCount(1, $detections);
		$facts = $detections[0]->getExplanationData()['facts'];
		$this->assertSame(5, $facts['names']);
		$this->assertSame(5, $facts['sources']);
		for ($i = 1; $i <= 5; $i++) {
			$this->assertCount(1, $this->bans->findActiveForKeys(['198.51.100.' . $i], time()), 'source ' . $i . ' is blocked');
		}
		$this->assertTrue($this->isFlagged(self::SPRAYED));
		$this->assertFalse($this->isFlagged('another password'));
	}

	public function testTheFlagCoversTomorrowsFingerprintToo(): void {
		$this->spray(5);
		$tomorrow = $this->createMock(\OCP\AppFramework\Utility\ITimeFactory::class);
		$tomorrow->method('getTime')->willReturn(time() + 86400);
		$fingerprinter = new Fingerprinter(Server::get(\OCP\IConfig::class), $tomorrow);
		$this->assertTrue($this->flags->isPasswordFlagged(array_map('bin2hex', $fingerprinter->passwordCandidates(self::SPRAYED))));
	}

	public function testAPasswordFlagLastsAtMostADayWhateverTheFlagDuration(): void {
		$this->settings->setGlobal(\OCA\IntrusionDetection\Config\GlobalSettings::FLAG_DURATION, 30 * 86400);
		$this->spray(5);
		$result = $this->db->getQueryBuilder()->select('flag_key', 'expires_at')->from('ids_flags')->executeQuery();
		$rows = $result->fetchAll();
		$result->closeCursor();
		$passwordFlags = array_filter($rows, static fn (array $row): bool => str_starts_with((string)$row['flag_key'], 'fp:'));
		$this->assertNotSame([], $passwordFlags);
		foreach ($passwordFlags as $row) {
			$this->assertLessThanOrEqual(time() + FlaggedSources::PASSWORD_FLAG_MAX_DURATION, (int)$row['expires_at']);
		}
		$until = array_column($this->detectionsOf(PasswordSpraying::ID)[0]->getActionList(), 'ref', 'type')['flag_password']['until'];
		$this->assertLessThanOrEqual(time() + FlaggedSources::PASSWORD_FLAG_MAX_DURATION, $until, 'The detection says when it really ends');
	}

	public function testDifferentPasswordsDoNotAddUp(): void {
		for ($i = 1; $i <= 6; $i++) {
			$this->failLogin('198.51.100.' . $i, 'user' . $i, 'password-' . $i);
		}
		$this->assertSame([], $this->detectionsOf(PasswordSpraying::ID));
	}

	public function testTheSameAccountTriedRepeatedlyIsNotSpraying(): void {
		for ($i = 1; $i <= 8; $i++) {
			$this->failLogin('198.51.100.' . $i, 'alice', self::SPRAYED);
		}
		$this->assertSame([], $this->detectionsOf(PasswordSpraying::ID));
	}

	public function testALaterAttemptWithAFlaggedPasswordIsBlockedAtOnce(): void {
		$this->spray(5);
		$this->failLogin('203.0.113.99', 'someone-new', self::SPRAYED);
		$this->assertCount(1, $this->bans->findActiveForKeys(['203.0.113.99'], time()));
		$joined = array_values(array_filter(
			$this->detectionsOf(PasswordSpraying::ID),
			static fn ($d): bool => $d->getIp() === '203.0.113.99',
		));
		$this->assertCount(1, $joined);
		$this->assertSame(PasswordSpraying::RULE_FLAGGED, $joined[0]->getExplanationData()['facts']['rule']);
	}

	public function testASprayingSourceThatComesBackKeepsItsSprayDetection(): void {
		$this->spray(5);
		$this->failLogin('198.51.100.5', 'someone-new', self::SPRAYED);
		$fromSource = array_values(array_filter(
			$this->detectionsOf(PasswordSpraying::ID),
			static fn ($d): bool => $d->getIp() === '198.51.100.5',
		));
		$byRule = [];
		foreach ($fromSource as $detection) {
			$byRule[$detection->getExplanationData()['facts']['rule']] = $detection;
		}
		$this->assertEqualsCanonicalizing([PasswordSpraying::RULE_SPRAY, PasswordSpraying::RULE_FLAGGED], array_keys($byRule), 'Joining the spray again is its own detection');
		$this->assertSame(5, $byRule[PasswordSpraying::RULE_SPRAY]->getExplanationData()['facts']['names'], 'The spray keeps its facts');
	}

	public function testAtMost500SourcesAreBlockedAndTheRestCounted(): void {
		for ($i = 0; $i < 549; $i++) {
			$this->storeAttempt('100.' . (64 + intdiv($i, 200)) . '.' . ($i % 200) . '.1', 'victim' . $i, password: self::SPRAYED);
		}
		$this->failLogin('100.70.0.1', 'victim-last', self::SPRAYED);
		$detection = $this->detectionsOf(PasswordSpraying::ID)[0];
		$facts = $detection->getExplanationData()['facts'];
		$this->assertSame(550, $facts['sources']);
		$this->assertSame(500, $facts['banTargets']);
		$this->assertLessThanOrEqual(501, $this->rows('ids_bans'), 'The current source and at most 500 others');
		$this->assertGreaterThanOrEqual(500, $this->rows('ids_bans'));

		$narrative = Server::get(NarrativeBuilder::class)->build($detection, Server::get(IFactory::class)->get(Application::APP_ID, 'en'));
		$this->assertStringContainsString('50 more addresses tried it', implode(' ', $narrative->happened));
	}

	public function testIpv6SourcesAreBlockedAsTheirSlash64(): void {
		for ($i = 1; $i <= 5; $i++) {
			$this->failLogin('2001:db8:' . $i . '::1', 'user' . $i, self::SPRAYED);
		}
		$this->assertCount(1, $this->bans->findActiveForKeys(['2001:db8:3::/64'], time()));
	}

	public function testObserveFlagsNothingAndBlocksNothing(): void {
		$this->settings->setMode(PasswordSpraying::ID, Mode::Observe);
		$this->spray(6);
		$detections = $this->detectionsOf(PasswordSpraying::ID);
		$this->assertNotSame([], $detections);
		$this->assertFalse($detections[0]->isEnforced());
		$this->assertSame(0, $this->rows('ids_bans'));
		$this->assertSame(0, $this->rows('ids_flags'));
	}

	public function testOffSkipsTheWork(): void {
		$this->settings->setMode(PasswordSpraying::ID, Mode::Off);
		$this->spray(6);
		$this->assertSame(0, $this->rows('ids_attempts'));
		$this->assertSame(0, $this->rows('ids_detections'));
	}

	public function testAppPasswordShapedAttemptsAreNotFingerprinted(): void {
		for ($i = 1; $i <= 6; $i++) {
			$this->failLogin('198.51.100.' . $i, 'user' . $i, 'ABCDE-FGHJK-LMNPQ-RSTWX-YZ234');
		}
		$this->assertSame([], $this->detectionsOf(PasswordSpraying::ID));
		foreach ($this->allRows('ids_attempts') as $row) {
			$this->assertSame(2, (int)$row['kind']);
			$this->assertNull($row['pw_fp']);
		}
	}

	private function spray(int $accounts): void {
		for ($i = 1; $i <= $accounts; $i++) {
			$this->failLogin('198.51.100.' . $i, 'user' . $i, self::SPRAYED);
		}
	}

	private function isFlagged(string $password): bool {
		return $this->flags->isPasswordFlagged(array_map('bin2hex', Server::get(Fingerprinter::class)->passwordCandidates($password)));
	}
}
