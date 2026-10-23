<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Check;

use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Db\Ban;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Notification\Db\AlertMapper;
use OCA\IntrusionDetection\Notification\UserAlerts;
use OCA\IntrusionDetection\Notification\UserMessages;
use OCA\IntrusionDetection\Response\BanExemptions;
use OCA\IntrusionDetection\Response\BanResult;
use OCA\IntrusionDetection\Response\BanService;
use OCA\IntrusionDetection\Response\Handlers\BanHandler;
use OCA\IntrusionDetection\Response\IAcceptedLogins;
use OCA\IntrusionDetection\Response\ResponseContext;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IGroupManager;
use OCP\IUser;
use OCP\IUserManager;
use OCP\Server;
use PHPUnit\Framework\Attributes\DataProvider;
use Test\TestCase;

/**
 * The rules generic code applies per check: which checks spare the address
 * of a lure, which no trusted login exempts from a block, which honour a
 * confirmed login of their account, and how often a user is told.
 */
class CheckPolicyTest extends TestCase {
	private const LURES = ['trap_url', 'injection_probe', 'share_bruteforce'];
	private const NEVER_TRUSTED = ['trap_url', 'injection_probe'];
	private const ACCOUNT_SCOPED = ['account_under_attack'];
	private const DAILY_USER_ALERTS = ['account_under_attack', 'step_up_refused_client', 'step_up_unconfirmed'];

	/**
	 * @return array<string, array{string}>
	 */
	public static function checks(): array {
		$ids = [];
		foreach (CheckRegistry::CHECKS as $class) {
			$ids[$class::ID] = [$class::ID];
		}
		return $ids;
	}

	#[DataProvider('checks')]
	public function testOnlyChecksAPlainLinkTriggersSpareTheAddressOfALure(string $checkId): void {
		$source = SourceKey::fromIp('198.51.100.7');
		$bans = $this->createMock(BanService::class);
		$bans->method('batch')->willReturnCallback(static fn (\Closure $work): mixed => $work());
		$ban = Ban::fromRow(['id' => '9']);
		$ban->setCidr('198.51.100.7/32');
		$bans->method('banMany')->willReturn([$source->ipKey => new BanResult(BanResult::BANNED, $ban)]);
		$handler = $this->build(BanHandler::class, [BanService::class => $bans]);
		$detection = Detection::fromRow(['id' => '5']);
		$draft = new DetectionDraft(checkId: $checkId, source: $source, lure: true);
		$outcome = $handler->apply(new ResponseContext($draft, $detection, Server::get(CheckRegistry::class)->get($checkId), true));
		$this->assertSame(in_array($checkId, self::LURES, true) ? 1 : 0, $outcome->ref['counts']['lure']);
	}

	#[DataProvider('checks')]
	public function testAnAdministratorsLoginExemptsTheAddressExceptFromTrapsAndProbes(string $checkId): void {
		$history = $this->createMock(IAcceptedLogins::class);
		$history->method('acceptedUidsFrom')->willReturn(['admin']);
		$groups = $this->createMock(IGroupManager::class);
		$groups->method('isAdmin')->willReturn(true);
		$exemptions = $this->build(BanExemptions::class, [IAcceptedLogins::class => $history, IGroupManager::class => $groups]);
		$result = $exemptions->forAddress(SourceKey::fromIp('198.51.100.7'), time(), $checkId);
		$this->assertSame(in_array($checkId, self::NEVER_TRUSTED, true) ? null : BanResult::SKIPPED_TRUSTED, $result?->outcome);
	}

	#[DataProvider('checks')]
	public function testOnlyChecksAboutOneAccountHonourItsConfirmedLogins(string $checkId): void {
		$history = $this->createMock(IAcceptedLogins::class);
		$history->method('acceptedUidsFrom')->willReturn(['alice']);
		$history->method('hasConfirmedLogin')->willReturn(true);
		$exemptions = $this->build(BanExemptions::class, [IAcceptedLogins::class => $history]);
		$result = $exemptions->forAddress(SourceKey::fromIp('198.51.100.7'), time(), $checkId, 'alice');
		$this->assertSame(in_array($checkId, self::ACCOUNT_SCOPED, true) ? BanResult::SKIPPED_TRUSTED : null, $result?->outcome);
	}

	#[DataProvider('checks')]
	public function testUsersAreToldHourlyOrDaily(string $checkId): void {
		$now = 1_800_000_000;
		$user = $this->createMock(IUser::class);
		$user->method('isEnabled')->willReturn(true);
		$users = $this->createMock(IUserManager::class);
		$users->method('get')->willReturn($user);
		$messages = $this->createMock(UserMessages::class);
		$messages->method('tellsUser')->willReturn(true);
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturn($now);
		$buckets = [];
		$alerts = $this->createMock(AlertMapper::class);
		$alerts->method('hit')->willReturnCallback(static function (string $id, string $key, int $bucket) use (&$buckets): array {
			$buckets[] = $bucket;
			throw new \RuntimeException('enough');
		});
		$userAlerts = $this->build(UserAlerts::class, [AlertMapper::class => $alerts, IUserManager::class => $users, UserMessages::class => $messages, ITimeFactory::class => $time]);
		$detection = Detection::fromRow(['id' => '5']);
		$detection->setCheckId($checkId);
		$detection->setUid('alice');
		try {
			$userAlerts->notify($detection);
		} catch (\RuntimeException) {
		}
		$this->assertSame([intdiv($now, in_array($checkId, self::DAILY_USER_ALERTS, true) ? 86400 : 3600)], $buckets);
	}

	public function testAReportOfAHeldBackBlockCanNeverBlockAndReportAgain(): void {
		$this->assertFalse(Server::get(CheckRegistry::class)->get('shared_address')->allowsResponse(ResponseType::Ban));
	}

	/**
	 * The class with the given dependencies, the real check registry and
	 * mocks for the rest.
	 *
	 * @template T of object
	 * @param class-string<T> $class
	 * @param array<class-string, object> $given
	 * @return T
	 */
	private function build(string $class, array $given): object {
		$args = [];
		foreach ((new \ReflectionClass($class))->getConstructor()?->getParameters() ?? [] as $parameter) {
			$type = (string)$parameter->getType();
			$args[] = $given[$type] ?? ($type === CheckRegistry::class ? Server::get(CheckRegistry::class) : $this->createMock($type));
		}
		return new $class(...$args);
	}
}
