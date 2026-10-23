<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Explain;

use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\Checks\AccountLocked\AccountLocked;
use OCA\IntrusionDetection\Check\Checks\AdminChange\AdminChange;
use OCA\IntrusionDetection\Check\Checks\InjectionProbe\InjectionProbe;
use OCA\IntrusionDetection\Check\Checks\PasswordSpraying\PasswordSpraying;
use OCA\IntrusionDetection\Check\Checks\ShareBruteforce\ShareBruteforce;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Explain\IAsksWasThisYou;
use OCA\IntrusionDetection\Explain\IExplainsToUser;
use OCA\IntrusionDetection\Explain\IKeepsFromUser;
use OCA\IntrusionDetection\Notification\UserMessages;
use OCP\IL10N;
use OCP\L10N\IFactory;
use OCP\Server;
use Psr\Container\ContainerInterface;
use Test\TestCase;

/**
 * Every check whose detections can reach the affected user has words for
 * that user ({@see IExplainsToUser}), or says that it keeps them from the
 * user ({@see IKeepsFromUser}). A detection reaches a user when it is
 * recorded with an account: this test reads the app's code for every
 * detection draft that is given a `uid:`.
 */
class UserTextsTest extends TestCase {
	private CheckRegistry $registry;

	protected function setUp(): void {
		parent::setUp();
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willReturnCallback(static fn (string $class): object => Server::get($class));
		$this->registry = new CheckRegistry($container);
	}

	public function testEveryCheckThatRecordsAnAccountHasUserTextOrKeepsItsDetectionsFromTheUser(): void {
		$missing = [];
		foreach (self::checksRecordingAnAccount() as $class) {
			if (!is_a($class, IExplainsToUser::class, true) && !is_a($class, IKeepsFromUser::class, true)) {
				$missing[] = $class;
			}
		}
		$this->assertSame([], $missing, 'Implement IExplainsToUser, or IKeepsFromUser when the user must not be told');
	}

	public function testTheScanFindsTheChecksThatRecordAnAccount(): void {
		$found = self::checksRecordingAnAccount();
		foreach ([AdminChange::class, AccountLocked::class, InjectionProbe::class, PasswordSpraying::class, ShareBruteforce::class] as $class) {
			$this->assertContains($class, $found);
		}
	}

	public function testChecksThatTellOrAskTheUserHaveUserText(): void {
		foreach ($this->registry->all() as $definition) {
			$class = $this->registry->classOf($definition->id);
			if ($definition->allowsResponse(ResponseType::NotifyUser) || is_a($class, IAsksWasThisYou::class, true)) {
				$this->assertTrue(is_a($class, IExplainsToUser::class, true), $definition->id . ' tells or asks the user but has no words for them');
			}
		}
	}

	public function testOnlyChangesOfTheAccountsOwnAdministrationRightsAreToldToIt(): void {
		$told = [];
		foreach ((new \ReflectionClass(AdminChange::class))->getConstants() as $name => $kind) {
			if (str_starts_with($name, 'KIND_') && Server::get(UserMessages::class)->tellsUser(self::detection(AdminChange::ID, ['kind' => $kind]))) {
				$told[] = $kind;
			}
		}
		$this->assertSame([AdminChange::KIND_ADMIN_GRANTED, AdminChange::KIND_ADMIN_REMOVED, AdminChange::KIND_SUBADMIN_GRANTED], $told);
	}

	public function testAdministrationRightsAreToldCalmly(): void {
		$check = Server::get(AdminChange::class);
		$subjects = [];
		foreach ([
			['kind' => AdminChange::KIND_ADMIN_GRANTED],
			['kind' => AdminChange::KIND_ADMIN_GRANTED, 'group' => 'ids-team', 'delegated' => ['Users']],
			['kind' => AdminChange::KIND_ADMIN_REMOVED],
			['kind' => AdminChange::KIND_ADMIN_REMOVED, 'group' => 'ids-team', 'delegated' => ['Users']],
			['kind' => AdminChange::KIND_SUBADMIN_GRANTED, 'group' => 'ids-team'],
		] as $facts) {
			$notice = $check->userNotice(self::detection(AdminChange::ID, $facts), self::l());
			$subjects[] = $notice->subject;
			$this->assertSame(['If you did not expect this, ask your administrators about it.'], $notice->advice);
		}
		$this->assertSame([
			'You were made an administrator',
			'You got administration rights',
			'You are no longer an administrator',
			'You left a group with administration rights',
			'You were made a group administrator',
		], $subjects);
		$this->assertSame(['You were removed from the group "ids-team", which has administration rights for some settings.'], $check->userNotice(self::detection(AdminChange::ID, ['kind' => AdminChange::KIND_ADMIN_REMOVED, 'group' => 'ids-team', 'delegated' => ['Users']]), self::l())->message);
	}

	public function testALockedAccountIsToldWhoLockedItAndAProbeIsNot(): void {
		$messages = Server::get(UserMessages::class);
		$locked = self::detection(AccountLocked::ID, ['sentTo' => 'a***@example.com', 'tokensEnded' => 2]);
		$this->assertTrue($messages->tellsUser($locked));
		$notice = Server::get(AccountLocked::class)->userNotice($locked, self::l());
		$this->assertSame('Your account was locked', $notice->subject);
		$this->assertSame('Your account was locked with the link that Nextcloud sent to your previous email address a***@example.com after it was changed.', $notice->message[0]);

		$this->assertFalse($messages->tellsUser(self::detection(InjectionProbe::ID, ['authenticated' => true])), 'For the administrators to judge');
		$this->assertFalse($messages->tellsUser(self::detection('retired_check', [])), 'A check that no longer exists has no words for the user');
	}

	/**
	 * @param array<string, mixed> $facts
	 */
	private static function detection(string $checkId, array $facts): Detection {
		$detection = new Detection();
		$detection->setCheckId($checkId);
		$detection->setUid('alice');
		$detection->setCreatedTime(time());
		$detection->setExplanationData(['facts' => $facts]);
		return $detection;
	}

	private static function l(): IL10N {
		return Server::get(IFactory::class)->get('intrusion_detection', 'en');
	}

	/**
	 * The check classes of the detection drafts in the app's code that are
	 * given an account.
	 *
	 * @return list<string>
	 */
	private static function checksRecordingAnAccount(): array {
		$byShortName = [];
		foreach (CheckRegistry::CHECKS as $class) {
			$byShortName[substr($class, (int)strrpos($class, '\\') + 1)] = $class;
		}
		$found = [];
		$files = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(dirname(__DIR__, 3) . '/lib', \FilesystemIterator::SKIP_DOTS));
		foreach ($files as $file) {
			if (!$file instanceof \SplFileInfo || $file->getExtension() !== 'php') {
				continue;
			}
			foreach (self::drafts((string)$file->getRealPath()) as [$check, $withAccount, $line]) {
				$where = $file->getFilename() . ':' . $line;
				$class = $byShortName[$check === 'self' ? $file->getBasename('.php') : $check] ?? null;
				self::assertNotNull($class, 'Name the check of the detection draft in ' . $where . ' as <Check>::ID, so that this test sees it');
				if ($withAccount) {
					$found[] = $class;
				}
			}
		}
		return array_values(array_unique($found));
	}

	/**
	 * The `new DetectionDraft(...)` calls in a file: the short name of the
	 * class whose ID is the `checkId:` argument, whether a `uid:` argument
	 * is given, and the line.
	 *
	 * @return list<array{string, bool, int}>
	 */
	private static function drafts(string $path): array {
		$tokens = array_values(array_filter(
			token_get_all((string)file_get_contents($path)),
			static fn (mixed $t): bool => !is_array($t) || !in_array($t[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true),
		));
		$drafts = [];
		$count = count($tokens);
		for ($i = 2; $i < $count; $i++) {
			$name = $tokens[$i - 1];
			if ($tokens[$i] !== '(' || !is_array($tokens[$i - 2]) || $tokens[$i - 2][0] !== T_NEW || !is_array($name) || !str_ends_with($name[1], 'DetectionDraft')) {
				continue;
			}
			$check = '';
			$withAccount = false;
			$depth = 0;
			for ($j = $i + 1; $j < $count; $j++) {
				$text = is_array($tokens[$j]) ? $tokens[$j][1] : $tokens[$j];
				if (in_array($text, ['(', '[', '{'], true)) {
					$depth++;
					continue;
				}
				if (in_array($text, [')', ']', '}'], true)) {
					if ($depth === 0) {
						break;
					}
					$depth--;
					continue;
				}
				if ($depth > 0 || ($tokens[$j + 1] ?? null) !== ':' || !in_array($tokens[$j - 1], [',', '('], true)) {
					continue;
				}
				if ($text === 'uid') {
					$withAccount = true;
				} elseif ($text === 'checkId' && is_array($tokens[$j + 2] ?? null) && is_array($tokens[$j + 3] ?? null) && $tokens[$j + 3][0] === T_DOUBLE_COLON && ($tokens[$j + 4][1] ?? null) === 'ID') {
					$check = substr($tokens[$j + 2][1], (int)strrpos('\\' . $tokens[$j + 2][1], '\\'));
				}
			}
			$drafts[] = [$check, $withAccount, $name[2]];
		}
		return $drafts;
	}
}
