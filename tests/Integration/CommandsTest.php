<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Command\Bans\Add;
use OCA\IntrusionDetection\Command\ReservedNames;
use OCA\IntrusionDetection\Command\Simulate;
use OCA\IntrusionDetection\Command\TrapPaths;
use OCA\IntrusionDetection\Command\User;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Response\AccountProtection;
use OCA\IntrusionDetection\Response\PasswordChangeService;
use OCP\IUserManager;
use OCP\Server;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;

#[Group('DB')]
class CommandsTest extends IntegrationTestCase {
	/**
	 * @return array<string, array{string, string}>
	 */
	public static function simulatable(): array {
		return [
			'credential stuffing' => ['credential_stuffing', 'failed to log in 10 times, trying 5 different accounts'],
			'password spraying' => ['password_spraying', 'one password was tried against 5 different accounts'],
			'account under attack' => ['account_under_attack', 'had 10 failed logins from 5 different addresses'],
			'reserved name' => ['reserved_name', 'tried to log in as "admin"'],
			'trap url' => ['trap_url', 'requested /wp-login[.]php'],
			'share token guessing' => ['share_bruteforce', 'tried 10 different share links that do not exist'],
			'reset abuse' => ['reset_probing', 'asked for password resets for 5 different names or email addresses'],
		];
	}

	#[DataProvider('simulatable')]
	public function testSimulateExplainsWithoutRecordingAnything(string $check, string $expected): void {
		[$code, $output] = $this->runCommand(Simulate::class, ['check' => $check]);
		$this->assertSame(Command::SUCCESS, $code);
		$this->assertStringContainsString($expected, $output);
		$this->assertStringContainsString(Simulate::TEST_ADDRESS, $output);
		$this->assertStringContainsString('Responses that would run', $output);
		foreach (self::tables() as $table) {
			$qb = $this->db->getQueryBuilder();
			$this->assertSame(0, (int)$qb->select($qb->func()->count('*'))->from($table)->executeQuery()->fetchOne(), $table . ' stays empty');
		}
	}

	public function testSimulationsShowOnlyTheResponsesOfTheSimulatedRule(): void {
		foreach (['share_bruteforce' => ['ban', 'notify_admin'], 'reset_probing' => ['ban']] as $check => $expected) {
			[, $output] = $this->runCommand(Simulate::class, ['check' => $check, '--output' => 'json']);
			$this->assertSame($expected, array_column(json_decode($output, true, 16, JSON_THROW_ON_ERROR)['responses'], 'type'), $check);
		}
	}

	public function testInternalChecksCannotBeSimulated(): void {
		$this->assertSame(Command::INVALID, $this->runCommand(Simulate::class, ['check' => 'manual'])[0]);
		$this->assertSame(Command::INVALID, $this->runCommand(Simulate::class, ['check' => 'no_such_check'])[0]);
	}

	/**
	 * @return array<string, array{array<string, string>, string}>
	 */
	public static function invalidBans(): array {
		return [
			'no duration' => [['--duration' => '0'], 'A block lasts from 5 minutes to 90 days.'],
			'shorter than the page allows' => [['--duration' => '60'], 'A block lasts from 5 minutes to 90 days.'],
			'longer than 90 days' => [['--duration' => '91d'], 'A block lasts from 5 minutes to 90 days.'],
			'a note longer than the page allows' => [['--note' => str_repeat('x', 256)], 'The note can have at most 255 characters.'],
			'not an address' => [['target' => 'example.com'], 'Enter an IPv4 address'],
			'a level that is no number' => [['--level' => 'abc'], 'The level must be 1, 2 or 3'],
			'level 4' => [['--level' => '4'], 'The level must be 1, 2 or 3'],
			'the server itself' => [['target' => '127.0.0.0/24'], 'never blocked'],
		];
	}

	/**
	 * @param array<string, string> $options
	 */
	#[DataProvider('invalidBans')]
	public function testBansByHandAreValidated(array $options, string $message): void {
		[$code, $output] = $this->runCommand(Add::class, $options + ['target' => '203.0.113.7']);
		$this->assertSame(Command::INVALID, $code);
		$this->assertStringContainsString($message, $output);
		$this->assertSame(0, Server::get(BanMapper::class)->countActive(time()));
	}

	public function testABanByHandWithADurationAndLevel(): void {
		[$code, $output] = $this->runCommand(Add::class, ['target' => '203.0.113.7', '--level' => '3', '--duration' => '90d']);
		$this->assertSame(Command::SUCCESS, $code, $output);
		$ban = Server::get(BanMapper::class)->findActiveForKeys(['203.0.113.7'], time())[0];
		$this->assertSame(3, $ban->getLevel());
		$this->assertEqualsWithDelta(time() + 90 * 86400, $ban->getExpiresAt(), 5);
	}

	public function testReservedNamesCommand(): void {
		[$code, $output] = $this->runCommand(ReservedNames::class, ['--add' => ['Root', 'nextcloud']]);
		$this->assertSame(Command::SUCCESS, $code);
		$this->assertStringContainsString('Reserved: root, nextcloud', $output);
		[$code, $output] = $this->runCommand(ReservedNames::class, ['--add' => ['admin']]);
		$this->assertSame(Command::INVALID, $code, 'admin is an existing account');
		$this->assertStringContainsString('existing account', $output);
		[, $output] = $this->runCommand(ReservedNames::class, ['--remove' => ['root']]);
		$this->assertStringContainsString('Reserved: nextcloud', $output);
	}

	public function testTrapPathsCommand(): void {
		[$code, $output] = $this->runCommand(TrapPaths::class, ['--add' => ['/old-admin', '/backup/*']]);
		$this->assertSame(Command::SUCCESS, $code);
		$this->assertStringContainsString('Your paths: /old-admin /backup/*', $output);
		$this->assertStringContainsString('/wp-login.php', $output);
		$this->assertStringContainsString('Reach Nextcloud only with the web server rule from the Blocks tab, on nginx: /.env /.git/ /.aws/ /.ds_store; on Apache with PHP-FPM: /wp-login.php /xmlrpc.php /adminer.php.', $output);
		$this->assertSame(Command::INVALID, $this->runCommand(TrapPaths::class, ['--add' => ['/remote.php/x']])[0]);
		[, $output] = $this->runCommand(TrapPaths::class, ['--remove' => ['/OLD-ADMIN']]);
		$this->assertStringContainsString('Your paths: /backup/*', $output);
	}

	public function testUserCommandEndsTheProtection(): void {
		$uid = 'ids-cmd-' . bin2hex(random_bytes(3));
		$user = Server::get(IUserManager::class)->createUser($uid, 'A-long-test-password-1');
		try {
			Server::get(AccountProtection::class)->protect($uid, time() + 3600);
			[, $output] = $this->runCommand(User::class, ['uid' => $uid]);
			$this->assertStringContainsString('Protection: until', $output);
			[, $output] = $this->runCommand(User::class, ['uid' => $uid, '--end-protection' => true]);
			$this->assertStringContainsString('has ended', $output);
			$this->assertStringContainsString('Protection: none.', $output);
			$this->assertSame(Command::INVALID, $this->runCommand(User::class, ['uid' => 'no-such-user-' . $uid])[0]);
		} finally {
			$user->delete();
		}
	}

	public function testUserCommandLiftsARequiredPasswordChange(): void {
		$uid = 'ids-cmd-' . bin2hex(random_bytes(3));
		$user = Server::get(IUserManager::class)->createUser($uid, 'A-long-test-password-1');
		try {
			Server::get(PasswordChangeService::class)->require($uid);
			[, $output] = $this->runCommand(User::class, ['uid' => $uid]);
			$this->assertStringContainsString('New password: required at the next login', $output);
			[, $output] = $this->runCommand(User::class, ['uid' => $uid, '--clear-forced-change' => true]);
			$this->assertStringContainsString($uid . ' no longer needs to choose a new password.', $output);
			$this->assertStringContainsString('New password: not required.', $output);
			$this->assertFalse(Server::get(PasswordChangeService::class)->isRequired($uid));
			[, $output] = $this->runCommand(User::class, ['uid' => $uid, '--clear-forced-change' => true]);
			$this->assertStringContainsString('did not need to choose a new password', $output);
		} finally {
			$user->delete();
		}
	}

	/**
	 * @param class-string<Command> $class
	 * @param array<string, mixed> $input
	 * @return array{0: int, 1: string}
	 */
	private function runCommand(string $class, array $input): array {
		$output = new BufferedOutput();
		$code = Server::get($class)->run(new ArrayInput($input), $output);
		return [$code, $output->fetch()];
	}
}
