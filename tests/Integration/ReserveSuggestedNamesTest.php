<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Check\Checks\ReservedName;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Learning\LearningService;
use OCA\IntrusionDetection\Repair\ReserveSuggestedNames;
use OCA\IntrusionDetection\Repair\StartLearningMode;
use OCA\IntrusionDetection\Traps\ReservedNames;
use OCP\IUserManager;
use OCP\Migration\IOutput;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Test\Util\User\Dummy;

/**
 * A fresh install reserves the suggested names, except those that are
 * accounts in any user backend, so the decoy admin account check works
 * without a setup step.
 */
#[Group('DB')]
class ReserveSuggestedNamesTest extends LoginFailureTestCase {
	private Dummy $directory;

	protected function setUp(): void {
		parent::setUp();
		// Stands in for a directory such as LDAP: its accounts are not in Nextcloud's own user table.
		$this->directory = new Dummy();
		$this->directory->createUser('root', 'A-long-test-password-root');
		Server::get(IUserManager::class)->registerBackend($this->directory);
	}

	protected function tearDown(): void {
		Server::get(IUserManager::class)->removeBackend($this->directory);
		parent::tearDown();
	}

	private function install(): void {
		$output = $this->createMock(IOutput::class);
		Server::get(ReserveSuggestedNames::class)->run($output);
		Server::get(StartLearningMode::class)->run($output);
	}

	public function testAFreshInstallReservesTheSuggestedNamesThatAreNoAccounts(): void {
		$this->user('support');
		$this->assertSame([], Server::get(ReservedNames::class)->list(), 'Nothing is reserved before the installation');

		$this->install();

		$users = Server::get(IUserManager::class);
		$expected = array_values(array_filter(ReservedNames::SUGGESTIONS, static fn (string $name): bool => !$users->userExists($name)));
		$reserved = Server::get(ReservedNames::class)->list();
		$this->assertSame($expected, $reserved);
		$this->assertContains('administrator', $reserved);
		$this->assertNotContains('support', $reserved, 'An account of Nextcloud itself');
		$this->assertNotContains('root', $reserved, 'An account of another user backend');
	}

	public function testALoginWithAReservedNameIsBlockedRightAfterInstallationEvenWhileLearning(): void {
		$this->install();
		$this->assertTrue(Server::get(LearningService::class)->isActive());

		$this->failLogin('203.0.113.150', 'administrator');
		$this->assertCount(1, $this->detectionsOf(ReservedName::ID));
		$this->assertCount(1, Server::get(BanMapper::class)->findActiveForKeys(['203.0.113.150'], time()), 'Reserved names act during learning, like decoys');

		Server::get(LearningService::class)->stop('test');
		$this->failLogin('203.0.113.151', 'Administrator');
		$this->assertCount(1, Server::get(BanMapper::class)->findActiveForKeys(['203.0.113.151'], time()));
	}

	public function testOnlyTheFirstInstallationReservesNames(): void {
		$this->settings->setGlobal(GlobalSettings::INSTALLED_AT, time() - 86400);
		$this->install();
		$this->assertSame([], Server::get(ReservedNames::class)->list(), 'An earlier installation keeps its names, even none');
	}
}
