<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Check\Checks\ReservedName\ReservedName;
use OCA\IntrusionDetection\Decoy\Db\DecoyMapper;
use OCA\IntrusionDetection\Decoy\DecoyFormat;
use OCA\IntrusionDetection\Decoy\DecoyService;
use OCA\IntrusionDetection\SetupCheck\TrapNameCollisionCheck;
use OCA\IntrusionDetection\State\AppState;
use OCA\IntrusionDetection\Traps\AccountNames;
use OCA\IntrusionDetection\Traps\TrapNameCollisions;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IUserManager;
use OCP\Server;
use OCP\Snowflake\ISnowflakeGenerator;
use PHPUnit\Framework\Attributes\Group;

/**
 * Reserved names and decoy login names that became accounts are looked up
 * when the names change and by the hourly job; the setup check only reads
 * the stored result.
 */
#[Group('DB')]
class TrapNameCollisionsTest extends IntegrationTestCase {
	private const UID = 'ids-trap-collision';

	protected function tearDown(): void {
		Server::get(IUserManager::class)->get(self::UID)?->delete();
		parent::tearDown();
	}

	public function testChangingTheNamesLooksThemUpAndReadingDoesNot(): void {
		Server::get(AppState::class)->setJson(TrapNameCollisions::STATE, ['reserved' => ['stale'], 'decoys' => [], 'checkedAt' => 1]);
		$this->settingsEditor()->setParam(ReservedName::ID, 'names', ['root', self::UID]);
		$this->assertSame([], Server::get(TrapNameCollisions::class)->all(), 'looked up again when the names changed');

		// The account appears later, for example from LDAP: only a refresh sees it.
		Server::get(IUserManager::class)->createUser(self::UID, 'A-long-test-password-' . self::UID);
		$accounts = $this->createMock(AccountNames::class);
		$accounts->expects($this->never())->method('exists');
		$reading = new TrapNameCollisions($this->checkSettings(), Server::get(DecoyMapper::class), $accounts, Server::get(ITimeFactory::class), Server::get(AppState::class));
		$this->assertSame([], $reading->all(), 'the stored result, without a lookup');
		$l = Server::get(\OCP\L10N\IFactory::class)->get('intrusion_detection', 'en');
		$this->assertNull((new TrapNameCollisionCheck($l, Server::get(\OCA\IntrusionDetection\Notification\AdminLinks::class), $reading, $this->checkSettings()))->finding($l));

		$this->assertSame([self::UID], Server::get(TrapNameCollisions::class)->refresh()['reserved']);
		$this->assertSame([self::UID], $reading->all());
	}

	public function testCreatingADecoyLooksTheNamesUp(): void {
		Server::get(IUserManager::class)->createUser(self::UID, 'A-long-test-password-' . self::UID);
		Server::get(AppState::class)->setJson(TrapNameCollisions::STATE, ['reserved' => [], 'decoys' => [], 'checkedAt' => 1]);
		$this->db->insertIfNotExist('*PREFIX*ids_decoys', ['id' => Server::get(ISnowflakeGenerator::class)->nextId(), 'label' => 'old', 'login_name' => self::UID, 'secret_hmac' => str_repeat('a', 64), 'format' => 'app_password', 'created_by' => 'admin', 'trigger_count' => 0], ['secret_hmac']);
		$this->assertSame([], Server::get(TrapNameCollisions::class)->all());

		Server::get(DecoyService::class)->create('new', null, DecoyFormat::AppPassword, 'admin');
		$this->assertSame([self::UID], Server::get(TrapNameCollisions::class)->all());
	}
}
