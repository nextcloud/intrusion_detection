<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Address\Verdict;
use OCA\IntrusionDetection\Check\Checks\AccountUnderAttack\AccountUnderAttack;
use OCA\IntrusionDetection\Check\Checks\BlocklistMatch\BlocklistMatch;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffing\CredentialStuffing;
use OCA\IntrusionDetection\Check\Checks\DecoyCredential\DecoyCredential;
use OCA\IntrusionDetection\Check\Checks\PasswordSpraying\PasswordSpraying;
use OCA\IntrusionDetection\Check\Checks\PasswordSpraying\PasswordSprayingRule;
use OCA\IntrusionDetection\Check\Checks\ReservedName\ReservedName;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Decoy\DecoyFormat;
use OCA\IntrusionDetection\Decoy\DecoyService;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Traps\ReservedNames;
use OCP\Server;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;

/**
 * The order of the failed-login chain: a decoy, and then a reserved name,
 * is answered on its own; only then is the attempt recorded, and only while
 * a check reads it; then the checks that read it run. Also the responses
 * each rule runs.
 */
#[Group('DB')]
class FailedLoginChainTest extends LoginFailureTestCase {
	private const SPRAYED = 'Summer2026!';

	public function testADecoyStopsTheChainAndRecordsNoAttempt(): void {
		Server::get(ReservedNames::class)->add(['administrator'], 'test');
		[, $secret] = Server::get(DecoyService::class)->create('old backup script', null, DecoyFormat::AppPassword, 'admin');

		$this->failLogin('198.51.100.7', 'administrator', $secret);

		$this->assertCount(1, $this->detectionsOf(DecoyCredential::ID));
		$this->assertSame([], $this->detectionsOf(ReservedName::ID), 'Nothing runs after a decoy');
		$this->assertSame(0, $this->rows('ids_attempts'));
	}

	public function testAReservedNameStopsTheRestAndRecordsNoAttempt(): void {
		Server::get(ReservedNames::class)->add(['administrator'], 'test');
		// One more failure from this address would be credential stuffing.
		for ($i = 0; $i < 9; $i++) {
			$this->storeAttempt('198.51.100.7', 'user' . ($i % 5));
		}

		$this->failLogin('198.51.100.7', 'administrator');

		$this->assertCount(1, $this->detectionsOf(ReservedName::ID));
		$this->assertSame([], $this->detectionsOf(CredentialStuffing::ID));
		$this->assertSame(9, $this->rows('ids_attempts'));
	}

	/**
	 * @return array<string, array{?string, int}>
	 */
	public static function attemptChecks(): array {
		return [
			'none' => [null, 0],
			'password spraying' => [PasswordSpraying::ID, 1],
			'credential stuffing' => [CredentialStuffing::ID, 1],
			'account under attack' => [AccountUnderAttack::ID, 1],
		];
	}

	#[DataProvider('attemptChecks')]
	public function testTheAttemptIsRecordedOnlyWhileACheckReadsIt(?string $running, int $rows): void {
		foreach ([PasswordSpraying::ID, CredentialStuffing::ID, AccountUnderAttack::ID] as $id) {
			$this->settingsEditor()->setMode($id, $id === $running ? Mode::Observe : Mode::Off);
		}
		$this->failLogin('198.51.100.7', 'someone');
		$this->assertSame($rows, $this->rows('ids_attempts'));
	}

	public function testAListedAddressIsRecordedBesideADecoy(): void {
		$this->settingsEditor()->setMode(BlocklistMatch::ID, Mode::Protect);
		$this->settingsEditor()->setGlobal(GlobalSettings::BLOCKLIST_SOURCES, json_encode([
			['id' => 'spamhaus_drop_v4', 'enabled' => true, 'mode' => 'observe'],
		]));
		[, $secret] = Server::get(DecoyService::class)->create('old backup script', null, DecoyFormat::AppPassword, 'admin');
		$this->requestContext->set(Verdict::CONTEXT_KEY, new Verdict(0, '', ['list:spamhaus_drop_v4'], time() + 300));
		$this->failLogin('198.51.100.7', 'anyone', $secret);

		$this->assertCount(1, $this->detectionsOf(BlocklistMatch::ID));
		$this->assertCount(1, $this->detectionsOf(DecoyCredential::ID));
	}

	public function testTheSprayRunsItsResponsesAndAJoiningAddressIsOnlyBlocked(): void {
		$this->settingsEditor()->setMode(CredentialStuffing::ID, Mode::Off);
		$this->settingsEditor()->setMode(AccountUnderAttack::ID, Mode::Off);
		for ($i = 1; $i <= 5; $i++) {
			$this->failLogin('198.51.100.' . $i, 'user' . $i, self::SPRAYED);
		}
		$this->failLogin('203.0.113.99', 'someone-new', self::SPRAYED);
		$this->failLogin('203.0.113.99', 'someone-else', self::SPRAYED);

		$byRule = [];
		foreach ($this->detectionsOf(PasswordSpraying::ID) as $detection) {
			$byRule[$detection->getExplanationData()['facts']['rule']] = self::actionTypes($detection);
		}
		ksort($byRule);
		$this->assertSame([
			PasswordSprayingRule::Flagged->value => ['ban'],
			PasswordSprayingRule::Spray->value => ['ban', 'flag_password', 'notify_admin'],
		], $byRule);
	}

	public function testADistributedAttackOnlyNotifiesTheAdministrators(): void {
		$this->settingsEditor()->setMode(PasswordSpraying::ID, Mode::Off);
		$this->settingsEditor()->setMode(AccountUnderAttack::ID, Mode::Off);
		$this->settingsEditor()->setParam(CredentialStuffing::ID, 'min_failures', 1000);
		for ($i = 0; $i < 99; $i++) {
			$this->storeAttempt('192.0.2.' . ($i % 25 + 1), 'victim' . ($i % 25), at: time() - 120);
		}
		$this->failLogin('192.0.2.1', 'victim99');

		$distributed = array_values(array_filter(
			$this->detectionsOf(CredentialStuffing::ID),
			static fn (Detection $d): bool => ($d->getExplanationData()['facts']['distributed'] ?? false) === true,
		));
		$this->assertCount(1, $distributed);
		$this->assertSame(['notify_admin'], self::actionTypes($distributed[0]));
	}

	/**
	 * @return list<string>
	 */
	private static function actionTypes(Detection $detection): array {
		$types = array_column($detection->getActionList(), 'type');
		sort($types);
		return $types;
	}
}
