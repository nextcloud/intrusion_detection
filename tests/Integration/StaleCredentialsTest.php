<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Command\Credentials\Stale;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\UserKeys;
use OCA\IntrusionDetection\Controller\StaleCredentialsApiController;
use OCA\IntrusionDetection\Db\StaleTokenMapper;
use OCA\IntrusionDetection\Definition\InvalidParamException;
use OCA\IntrusionDetection\Notification\Notifier;
use OCA\IntrusionDetection\SetupCheck\Finding;
use OCA\IntrusionDetection\SetupCheck\StaleCredentialsCheck;
use OCA\IntrusionDetection\StaleCredential\StaleCredentialNotices;
use OCA\IntrusionDetection\StaleCredential\StaleCredentials;
use OCA\IntrusionDetection\StaleCredential\StaleCredentialSweep;
use OCA\IntrusionDetection\State\AppState;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Attribute\PasswordConfirmationRequired;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Authentication\Token\IProvider;
use OCP\Authentication\Token\IToken;
use OCP\Config\IUserConfig;
use OCP\DB\QueryBuilder\IQueryBuilder;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IUser;
use OCP\IUserManager;
use OCP\L10N\IFactory;
use OCP\Log\Audit\CriticalActionPerformedEvent;
use OCP\Notification\IManager as INotificationManager;
use OCP\Notification\INotification;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;

/**
 * App passwords and remembered browsers unused for 90 days: found by age,
 * listed and removed only for their own user, reminded at most monthly,
 * listed and removed by occ, removed automatically only when switched on,
 * and never shown with a secret.
 */
#[Group('DB')]
class StaleCredentialsTest extends AccountTestCase {
	private const DAY = 86400;

	private int $now;
	/** @var list<string> every secret created, none of which may ever be shown */
	private array $secrets = [];
	/** @var list<CriticalActionPerformedEvent> */
	private array $audited = [];
	private \Closure $auditListener;

	protected function setUp(): void {
		parent::setUp();
		$this->now = time();
		CapturingNotificationApp::$processed = [];
		$this->auditListener = function (CriticalActionPerformedEvent $e): void {
			$this->audited[] = $e;
		};
		Server::get(IEventDispatcher::class)->addListener(CriticalActionPerformedEvent::class, $this->auditListener);
	}

	protected function tearDown(): void {
		Server::get(IEventDispatcher::class)->removeListener(CriticalActionPerformedEvent::class, $this->auditListener);
		parent::tearDown();
	}

	public function testOnlyAppPasswordsAndRememberedBrowsersUnusedFor90DaysCount(): void {
		$user = $this->newUser('stale');
		$oldApp = $this->credential($user, IToken::PERMANENT_TOKEN, 'Thunderbird', 91);
		$oldBrowser = $this->credential($user, IToken::TEMPORARY_TOKEN, 'Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0', 120, IToken::REMEMBER);
		$this->credential($user, IToken::PERMANENT_TOKEN, 'DAVx5', 89);
		$this->credential($user, IToken::TEMPORARY_TOKEN, 'Old session without "Remember me"', 120, IToken::DO_NOT_REMEMBER);
		$this->credential($user, IToken::WIPE_TOKEN, 'Phone to wipe', 200);

		$list = $this->credentials()->forUser($user->getUID(), $this->l());

		$this->assertSame([$oldBrowser, $oldApp], array_column($list, 'id'), 'longest unused first');
		$this->assertSame(['Firefox on Linux', 'Thunderbird'], array_column($list, 'name'));
		$this->assertSame(['session', 'app_password'], array_column($list, 'kind'));
		$this->assertSame($this->now - 120 * self::DAY, $list[0]['lastUsed']);

		$mapper = Server::get(StaleTokenMapper::class);
		$accounts = array_values(array_filter($mapper->accounts($this->now - 90 * self::DAY, null, 10000), fn (array $a): bool => $a['uid'] === $user->getUID()));
		$this->assertSame([['uid' => $user->getUID(), 'appPasswords' => 1, 'sessions' => 1, 'oldest' => $this->now - 120 * self::DAY, 'newest' => $this->now - 91 * self::DAY]], $accounts);
		$this->assertSame([$oldApp, $oldBrowser], array_column($mapper->tokens($this->now - 90 * self::DAY, $user->getUID(), 0, 100), 'id'));
	}

	public function testTheMapperCountsAccountsAndCredentialsAndPagesByUid(): void {
		$mapper = Server::get(StaleTokenMapper::class);
		$before = $mapper->count($this->now - 90 * self::DAY);
		$a = $this->newUser('stale-a');
		$b = $this->newUser('stale-b');
		$this->credential($a, IToken::PERMANENT_TOKEN, 'One', 100);
		$this->credential($a, IToken::PERMANENT_TOKEN, 'Two', 100);
		$this->credential($b, IToken::TEMPORARY_TOKEN, 'Browser', 100, IToken::REMEMBER);

		$after = $mapper->count($this->now - 90 * self::DAY);
		$this->assertSame($before['credentials'] + 3, $after['credentials']);
		$this->assertSame($before['accounts'] + 2, $after['accounts']);

		$seen = [];
		$after = null;
		do {
			$page = $mapper->accounts($this->now - 90 * self::DAY, $after, 1);
			foreach ($page as $row) {
				$seen[] = $row['uid'];
				$after = $row['uid'];
			}
		} while ($page !== []);
		$this->assertContains($a->getUID(), $seen);
		$this->assertContains($b->getUID(), $seen);
		$this->assertSame(count($seen), count(array_unique($seen)), 'each account on one page only');
	}

	public function testUsersSeeAndRemoveOnlyTheirOwnUnusedCredentials(): void {
		$mine = $this->newUser('stale-mine');
		$other = $this->newUser('stale-other');
		$current = $this->credential($mine, IToken::TEMPORARY_TOKEN, 'Firefox', 200, IToken::REMEMBER);
		$this->session->id = (string)end($this->secrets);
		$this->sessionUser = $mine;
		$myOld = $this->credential($mine, IToken::PERMANENT_TOKEN, 'Thunderbird', 100);
		$myOther = $this->credential($mine, IToken::PERMANENT_TOKEN, 'Old script', 150);
		$myFresh = $this->credential($mine, IToken::PERMANENT_TOKEN, 'Phone', 2);
		$theirs = $this->credential($other, IToken::PERMANENT_TOKEN, 'Their laptop', 300);

		$controller = $this->controller();
		$listed = $controller->index()->getData();
		$this->assertSame([$myOther, $myOld], array_column($listed, 'id'), 'neither the session of this request nor anyone else\'s');

		foreach ([$theirs, $myFresh, $current, 999999999] as $id) {
			$response = $controller->destroy($id);
			$this->assertSame(Http::STATUS_NOT_FOUND, $response->getStatus());
			$this->assertSame('not_found', $response->getData()['reason']);
		}
		$this->assertTrue($this->tokenExists($theirs));
		$this->assertTrue($this->tokenExists($myFresh));
		$this->assertTrue($this->tokenExists($current));

		$this->assertSame(['removed' => $myOld], $controller->destroy($myOld)->getData());
		$this->assertFalse($this->tokenExists($myOld));
		$this->assertSame([], CapturingNotificationApp::$processed, 'the reminder stays while one is left');

		$this->assertSame(['removed' => 1], $controller->destroyAll()->getData());
		$this->assertFalse($this->tokenExists($myOther));
		$this->assertTrue($this->tokenExists($myFresh));
		$this->assertTrue($this->tokenExists($theirs));
		$this->assertTrue($this->tokenExists($current));
		$this->assertSame([], $controller->index()->getData());
		$this->assertNotEmpty(array_filter(CapturingNotificationApp::$processed, static fn (INotification $n): bool => $n->getObjectType() === StaleCredentialNotices::OBJECT_REMINDER && $n->getObjectId() === $mine->getUID()), 'the reminder is taken back');

		$this->assertTrue($this->wasAudited('removed an app password or device unused for 90 days: Thunderbird'));
	}

	public function testRemovingNeedsTheResentPasswordAndThePage(): void {
		foreach (['destroy', 'destroyAll'] as $method) {
			$attributes = (new \ReflectionMethod(StaleCredentialsApiController::class, $method))->getAttributes(PasswordConfirmationRequired::class);
			$this->assertCount(1, $attributes, $method);
		}
		$this->appConfig->setValueBool(Application::APP_ID, GlobalSettings::PERSONAL_PAGE_ENABLED, false);
		$this->sessionUser = $this->newUser('stale-page');
		$this->expectException(\OCP\AppFramework\OCS\OCSNotFoundException::class);
		$this->controller()->index();
	}

	public function testUsersAreRemindedOnceAndAgainOnlyAfterAMonthWithSomethingNew(): void {
		$user = $this->newUser('stale-remind');
		$this->credential($user, IToken::PERMANENT_TOKEN, 'Thunderbird', 100);
		$this->credential($user, IToken::PERMANENT_TOKEN, 'Old script', 95);
		$this->credential($user, IToken::TEMPORARY_TOKEN, 'Firefox', 80, IToken::REMEMBER);

		$this->sweep()->run();
		$reminders = $this->notificationsFor($user->getUID(), Notifier::SUBJECT_STALE_REMINDER);
		$this->assertCount(1, $reminders);
		$this->assertSame(['appPasswords' => 2, 'sessions' => 0, 'days' => 90], $reminders[0]->getSubjectParameters());
		$this->assertSame($this->now, Server::get(IUserConfig::class)->getValueInt($user->getUID(), Application::APP_ID, UserKeys::STALE_CREDENTIALS_NOTIFIED_AT));
		$this->assertSame('You have 2 app passwords you haven\'t used for 3 months', $this->prepared($reminders[0])->getParsedSubject());

		$this->assertNull($this->sweep()->runIfDue(), 'once a day');
		$this->now += 29 * self::DAY;
		$this->sweep()->run();
		$this->assertCount(1, $this->notificationsFor($user->getUID(), Notifier::SUBJECT_STALE_REMINDER), 'not again within 30 days');

		// The browser became stale 10 days after the reminder, but within the month.
		$this->now += 2 * self::DAY;
		$this->assertNotNull($this->sweep()->runIfDue());
		$reminders = $this->notificationsFor($user->getUID(), Notifier::SUBJECT_STALE_REMINDER);
		$this->assertCount(2, $reminders, 'after a month, with a credential that became unused since');
		$this->assertSame(['appPasswords' => 2, 'sessions' => 1, 'days' => 90], $reminders[1]->getSubjectParameters());
		$this->assertSame('You have 3 app passwords and devices you haven\'t used for 3 months', $this->prepared($reminders[1])->getParsedSubject());

		$this->now += 40 * self::DAY;
		$this->sweep()->run();
		$this->assertCount(2, $this->notificationsFor($user->getUID(), Notifier::SUBJECT_STALE_REMINDER), 'nothing new: no reminder');
	}

	public function testDisabledAccountsAreNotReminded(): void {
		$user = $this->newUser('stale-disabled');
		$this->credential($user, IToken::PERMANENT_TOKEN, 'Thunderbird', 100);
		$user->setEnabled(false);
		$this->sweep()->run();
		$this->assertSame([], $this->notificationsFor($user->getUID()));
	}

	public function testNothingIsRemovedAutomaticallyByDefault(): void {
		$user = $this->newUser('stale-keep');
		$old = $this->credential($user, IToken::PERMANENT_TOKEN, 'Thunderbird', 400);

		$result = $this->sweep()->run();

		$this->assertSame(0, $result['removed']);
		$this->assertTrue($this->tokenExists($old));
		$this->assertSame([], $this->notificationsFor($user->getUID(), Notifier::SUBJECT_STALE_REMOVED));
	}

	public function testAutomaticRemovalRemovesWhatIsOlderThanTheSettingAndTellsTheUserOnce(): void {
		$this->settings->setGlobal(GlobalSettings::STALE_CREDENTIALS_REMOVE_DAYS, 120);
		$user = $this->newUser('stale-remove');
		$gone = $this->credential($user, IToken::PERMANENT_TOKEN, 'Thunderbird', 130);
		$goneBrowser = $this->credential($user, IToken::TEMPORARY_TOKEN, 'Firefox', 200, IToken::REMEMBER);
		$kept = $this->credential($user, IToken::PERMANENT_TOKEN, 'DAVx5', 100);
		$fresh = $this->credential($user, IToken::PERMANENT_TOKEN, 'Phone', 1);

		$result = $this->sweep()->run();

		$this->assertGreaterThanOrEqual(2, $result['removed']);
		$this->assertFalse($this->tokenExists($gone));
		$this->assertFalse($this->tokenExists($goneBrowser));
		$this->assertTrue($this->tokenExists($kept));
		$this->assertTrue($this->tokenExists($fresh));
		$notices = $this->notificationsFor($user->getUID(), Notifier::SUBJECT_STALE_REMOVED);
		$this->assertCount(1, $notices);
		$this->assertSame(['appPasswords' => 1, 'sessions' => 1, 'days' => 120, 'names' => ['Thunderbird', 'Firefox']], $notices[0]->getSubjectParameters());
		$prepared = $this->prepared($notices[0]);
		$this->assertSame('Removed 2 app passwords and devices you had not used for 120 days', $prepared->getParsedSubject());
		$this->assertStringContainsString('Removed: Thunderbird, Firefox.', $prepared->getParsedMessage());
		$this->assertTrue($this->wasAudited('the daily job removed 2 app passwords and devices of ' . $user->getUID() . ' unused for 120 days'));

		$this->sweep()->run();
		$this->assertCount(1, $this->notificationsFor($user->getUID(), Notifier::SUBJECT_STALE_REMOVED), 'told once');
		$this->assertTrue($this->tokenExists($kept));
	}

	public function testAutomaticRemovalNeedsAtLeast90Days(): void {
		try {
			$this->settings->setGlobal(GlobalSettings::STALE_CREDENTIALS_REMOVE_DAYS, 30);
			$this->fail('30 days were accepted');
		} catch (InvalidParamException $e) {
			$this->assertSame('zero_or_at_least', $e->reason);
		}
		$this->settings->setGlobal(GlobalSettings::STALE_CREDENTIALS_REMOVE_DAYS, 90);
		$this->assertSame(90, $this->sweep()->removeDays());
		$this->settings->setGlobal(GlobalSettings::STALE_CREDENTIALS_REMOVE_DAYS, 0);
		$this->assertSame(0, $this->sweep()->removeDays());
	}

	public function testTheSetupCheckGivesTheInstanceWideCounts(): void {
		$check = Server::get(StaleCredentialsCheck::class);
		$a = $this->newUser('stale-tip-a');
		$b = $this->newUser('stale-tip-b');
		$this->credential($a, IToken::PERMANENT_TOKEN, 'One', 100);
		$this->credential($a, IToken::PERMANENT_TOKEN, 'Two', 100);
		$this->credential($b, IToken::PERMANENT_TOKEN, 'Three', 100);
		$counts = Server::get(StaleCredentialSweep::class)->recount();

		$finding = $check->finding($this->l());

		$this->assertNotNull($finding);
		$this->assertSame(Finding::LEVEL_INFO, $finding->level, 'a tip, not a problem');
		$this->assertStringContainsString($counts['credentials'] . ' app passwords and devices have not been used for 3 months', $finding->title);
		$this->assertStringContainsString($counts['accounts'] . ' accounts have app passwords', $finding->text);
		$this->assertStringContainsString('occ intrusion:credentials:stale --revoke', $finding->fix);
	}

	public function testTheHourlyJobCountsAgainBetweenTheDailyRuns(): void {
		$this->sweep()->run();
		$counted = $this->sweep()->counts()['credentials'];
		$user = $this->newUser('stale-count');
		$this->credential($user, IToken::PERMANENT_TOKEN, 'Thunderbird', 100);
		$this->assertSame($counted, $this->sweep()->counts()['credentials'], 'read from the stored counts');

		$this->now += 3600;
		$this->assertNull($this->sweep()->runIfDue());
		$this->assertSame($counted + 1, $this->sweep()->counts()['credentials']);
		$this->assertSame([], $this->notificationsFor($user->getUID()), 'reminders only come with the daily run');
	}

	public function testOccListsAndRevokesWithoutSecrets(): void {
		$user = $this->newUser('stale-occ');
		$other = $this->newUser('stale-occ-other');
		$this->now = time();
		$old = $this->credential($user, IToken::PERMANENT_TOKEN, 'Thunderbird', 100);
		$fresh = $this->credential($user, IToken::PERMANENT_TOKEN, 'Phone', 1);
		$theirs = $this->credential($other, IToken::PERMANENT_TOKEN, 'Their script', 100);

		[$code, $output] = $this->runCommand(['--user' => $user->getUID()]);
		$this->assertSame(Command::SUCCESS, $code);
		$this->assertStringContainsString('1 app password or remembered browser of 1 account has not been used for 90 days.', $output);
		$this->assertStringContainsString('Thunderbird', $output);
		$this->assertStringNotContainsString('Phone', $output);
		$this->assertStringNotContainsString('Their script', $output);
		$this->assertStringContainsString('run this again with --revoke', $output);
		$this->assertTrue($this->tokenExists($old));

		[, $json] = $this->runCommand(['--user' => $user->getUID(), '--output' => 'json']);
		$data = json_decode($json, true, 16, JSON_THROW_ON_ERROR);
		$this->assertSame([['id' => $old, 'user' => $user->getUID(), 'type' => 'app_password', 'name' => 'Thunderbird', 'last_used' => $this->now - 100 * self::DAY]], $data['credentials']);

		[$code] = $this->runCommand(['--user' => $user->getUID(), '--revoke' => true, '--days' => '10']);
		$this->assertSame(Command::INVALID, $code, 'removing needs at least 30 days');
		[$code] = $this->runCommand(['--user' => 'no-such-account-' . bin2hex(random_bytes(3))]);
		$this->assertSame(Command::INVALID, $code);

		[$code, $output] = $this->runCommand(['--user' => $user->getUID(), '--revoke' => true]);
		$this->assertSame(Command::SUCCESS, $code);
		$this->assertStringContainsString('Removed 1 of them', $output);
		$this->assertFalse($this->tokenExists($old));
		$this->assertTrue($this->tokenExists($fresh));
		$this->assertTrue($this->tokenExists($theirs));
		$this->assertCount(1, $this->notificationsFor($user->getUID(), Notifier::SUBJECT_STALE_REMOVED));
		$this->assertNoSecret($output . $json);
	}

	public function testNoSecretIsEverShown(): void {
		$user = $this->newUser('stale-secret');
		$this->sessionUser = $user;
		$this->credential($user, IToken::PERMANENT_TOKEN, 'Thunderbird', 100);
		$this->credential($user, IToken::TEMPORARY_TOKEN, 'Firefox', 100, IToken::REMEMBER);

		$listed = $this->controller()->index()->getData();
		foreach ($listed as $row) {
			$this->assertSame(['id', 'name', 'kind', 'lastUsed'], array_keys($row));
		}
		foreach (Server::get(StaleTokenMapper::class)->tokens($this->now - 90 * self::DAY, $user->getUID(), 0, 10) as $row) {
			$this->assertSame(['id', 'uid', 'name', 'type', 'lastActivity'], array_keys($row));
		}
		$this->settings->setGlobal(GlobalSettings::STALE_CREDENTIALS_REMOVE_DAYS, 90);
		$this->sweep()->run();
		$notifications = $this->notificationsFor($user->getUID());
		$this->assertNotEmpty($notifications);

		$shown = json_encode($listed, JSON_THROW_ON_ERROR)
			. json_encode(array_map(fn (INotification $n): array => [$n->getSubjectParameters(), $this->prepared($n)->getParsedSubject(), $this->prepared($n)->getParsedMessage()], $notifications), JSON_THROW_ON_ERROR)
			. json_encode(array_map(static fn (CriticalActionPerformedEvent $e): array => [$e->getLogMessage(), $e->getParameters()], $this->audited), JSON_THROW_ON_ERROR);
		$this->assertNoSecret($shown);
	}

	/**
	 * A real token of core's provider, last used $daysAgo days before now.
	 */
	private function credential(IUser $user, int $type, string $name, int $daysAgo, ?int $remember = null): int {
		$secret = bin2hex(random_bytes(36));
		$this->secrets[] = $secret;
		$password = 'A-long-test-password-' . $user->getUID();
		$token = $this->tokens->generateToken($secret, $user->getUID(), $user->getUID(), $password, $name, $type, $remember ?? IToken::DO_NOT_REMEMBER);
		$this->age($token->getId(), $daysAgo);
		return $token->getId();
	}

	private function age(int $tokenId, int $daysAgo): void {
		$qb = $this->db->getQueryBuilder();
		$qb->update('authtoken')
			->set('last_activity', $qb->createNamedParameter($this->now - $daysAgo * self::DAY, IQueryBuilder::PARAM_INT))
			->where($qb->expr()->eq('id', $qb->createNamedParameter($tokenId, IQueryBuilder::PARAM_INT)))
			->executeStatement();
	}

	private function time(): ITimeFactory {
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturnCallback(fn (): int => $this->now);
		return $time;
	}

	private function credentials(): StaleCredentials {
		return new StaleCredentials($this->tokens, Server::get(IProvider::class), $this->currentSession, $this->time(), Server::get(AuditLogger::class));
	}

	private function sweep(): StaleCredentialSweep {
		$time = $this->time();
		return new StaleCredentialSweep(
			Server::get(StaleTokenMapper::class),
			$this->credentials(),
			new StaleCredentialNotices(Server::get(INotificationManager::class), $time),
			$this->settings,
			Server::get(AppState::class),
			Server::get(IUserConfig::class),
			Server::get(IUserManager::class),
			$time,
			Server::get(LoggerInterface::class),
		);
	}

	private function controller(): StaleCredentialsApiController {
		return new StaleCredentialsApiController(
			Server::get(IRequest::class),
			$this->userSession,
			$this->credentials(),
			new StaleCredentialNotices(Server::get(INotificationManager::class), $this->time()),
			$this->settings,
			$this->l(),
		);
	}

	private function l(): IL10N {
		return Server::get(IFactory::class)->get(Application::APP_ID, 'en');
	}

	private function prepared(INotification $notification): INotification {
		return Server::get(Notifier::class)->prepare(clone $notification, 'en');
	}

	/**
	 * @param array<string, mixed> $input
	 * @return array{0: int, 1: string}
	 */
	private function runCommand(array $input): array {
		$output = new BufferedOutput();
		$code = Server::get(Stale::class)->run(new ArrayInput($input), $output);
		return [$code, $output->fetch()];
	}

	private function wasAudited(string $text): bool {
		foreach ($this->audited as $event) {
			if (str_contains(vsprintf($event->getLogMessage(), array_values($event->getParameters())), $text)) {
				return true;
			}
		}
		return false;
	}

	private function assertNoSecret(string $shown): void {
		foreach ($this->secrets as $secret) {
			$this->assertStringNotContainsString($secret, $shown);
			$this->assertStringNotContainsString(hash('sha512', $secret), $shown);
		}
		$this->assertStringNotContainsString('A-long-test-password-', $shown);
		$this->assertStringNotContainsString('BEGIN', $shown, 'no key');
	}
}
