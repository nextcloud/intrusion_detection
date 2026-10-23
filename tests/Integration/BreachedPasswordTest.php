<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Psr7\Request;
use OC\Memcache\ArrayCache;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Breach\PwnedPasswordsClient;
use OCA\IntrusionDetection\Check\Checks\BreachedPassword\BreachedPassword;
use OCA\IntrusionDetection\Check\Checks\BreachedPassword\BreachedPasswordDetector;
use OCA\IntrusionDetection\Check\Checks\BreachedPassword\BreachedPasswordFacts;
use OCA\IntrusionDetection\Command\User as UserCommand;
use OCA\IntrusionDetection\Config\Lexicon;
use OCA\IntrusionDetection\Config\UserKeys;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Explain\CheckPresenter;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Listener\BreachedPasswordListener;
use OCA\IntrusionDetection\Listener\BreachResetListener;
use OCA\IntrusionDetection\Login\InteractiveLogin;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\ServerAddresses;
use OCA\IntrusionDetection\Notification\AdminAlerts;
use OCA\IntrusionDetection\Notification\Notifier;
use OCA\IntrusionDetection\Signal\InteractivePasswordLogin;
use OCA\IntrusionDetection\Signal\SignalDispatcher;
use OCA\IntrusionDetection\Tests\BasicAuthServer;
use OCA\IntrusionDetection\Tests\Unit\Cache\FixedCaches;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Config\IUserConfig;
use OCP\Http\Client\IClient;
use OCP\Http\Client\IClientService;
use OCP\Http\Client\IResponse;
use OCP\IConfig;
use OCP\IRequest;
use OCP\IUser;
use OCP\IUserManager;
use OCP\L10N\IFactory;
use OCP\Notification\IManager as INotificationManager;
use OCP\Security\Bruteforce\IThrottler;
use OCP\Security\ICrypto;
use OCP\Server;
use OCP\User\Events\PasswordUpdatedEvent;
use OCP\User\Events\UserLoggedInEvent;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Container\ContainerInterface;
use Psr\Log\AbstractLogger;
use Psr\Log\LoggerInterface;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;

/**
 * The breached password check end to end: the login listener, the detector,
 * the stored per-account values and the detection, with the Pwned Passwords
 * service replaced by a mocked HTTP client. Never contacts the internet.
 */
#[Group('DB')]
class BreachedPasswordTest extends IntegrationTestCase {
	use BasicAuthServer;

	/** SHA-1 21BD12DC183F740EE76F27B78EB39C8AD972A757 */
	public const PASSWORD = 'P@ssw0rd';
	public const SUFFIX = '2DC183F740EE76F27B78EB39C8AD972A757';

	protected DetectionMapper $detections;
	protected IUser $user;
	/** @var list<string> the requested URLs */
	protected array $requests = [];
	/** How often the service counts the password; null makes the request time out */
	protected ?int $listCount = 52579;
	/** The hash suffix the mocked range lists */
	protected string $suffix = self::SUFFIX;
	protected int $now;
	/** @var array<string, string> */
	protected array $headers = [];
	protected string $method = 'POST';
	protected string $path = '/login';
	protected string $remoteAddress = '198.51.100.20';
	protected bool $bypassListed = false;
	/** A memory cache the test can read, or null for none */
	protected ?ArrayCache $cache = null;
	/** @var list<string> every line the app logged */
	protected array $logged = [];

	protected function setUp(): void {
		parent::setUp();
		$this->detections = Server::get(DetectionMapper::class);
		$this->now = time();
		$uid = 'ids-breach-' . bin2hex(random_bytes(4));
		$user = Server::get(IUserManager::class)->createUser($uid, 'A-long-test-password-' . $uid);
		$this->assertInstanceOf(IUser::class, $user);
		$this->user = $user;
	}

	protected function tearDown(): void {
		Server::get(IUserConfig::class)->deleteUserConfig($this->user->getUID(), Application::APP_ID, UserKeys::BREACH_CHECKED_AT);
		Server::get(IUserConfig::class)->deleteUserConfig($this->user->getUID(), Application::APP_ID, UserKeys::BREACHED);
		$this->user->delete();
		parent::tearDown();
	}

	protected function logger(): LoggerInterface {
		return new class($this->logged) extends AbstractLogger {
			/** @param list<string> $lines */
			public function __construct(
				private array &$lines,
			) {
			}

			public function log($level, string|\Stringable $message, array $context = []): void {
				$this->lines[] = $message . ' ' . json_encode($context, JSON_PARTIAL_OUTPUT_ON_ERROR);
			}
		};
	}

	/**
	 * A fresh detector, as in a new request, with the mocked service and the
	 * test's clock and address.
	 */
	protected function detector(): BreachedPasswordDetector {
		$client = $this->createMock(IClient::class);
		$client->method('get')->willReturnCallback(function (string $url): IResponse {
			$this->requests[] = $url;
			if ($this->listCount === null) {
				throw new ConnectException('cURL error 28: Operation timed out for ' . $url, new Request('GET', $url));
			}
			$response = $this->createMock(IResponse::class);
			$response->method('getStatusCode')->willReturn(200);
			$response->method('getBody')->willReturn("0018A45C4D1DEF81644B54AB7F969B88D65:10\r\n" . $this->suffix . ':' . $this->listCount . "\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:0");
			return $response;
		});
		$clientService = $this->createMock(IClientService::class);
		$clientService->method('newClient')->willReturn($client);
		// Without a memory cache, every check that reaches the service is counted.
		$cacheFactory = $this->cache === null ? FixedCaches::none() : new FixedCaches($this->cache);
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturnCallback(fn (): int => $this->now);
		$throttler = $this->createMock(IThrottler::class);
		$throttler->method('isBypassListed')->willReturnCallback(fn (): bool => $this->bypassListed);

		return new BreachedPasswordDetector(
			$this->checkSettings(),
			new PwnedPasswordsClient($clientService, $cacheFactory, Server::get(ICrypto::class), $this->logger()),
			Server::get(IUserConfig::class),
			new RemoteAddressResolver($this->request(), $throttler, Server::get(ServerAddresses::class)),
			$time,
		);
	}

	/**
	 * @return IRequest&MockObject
	 */
	protected function request(): IRequest {
		$request = $this->createMock(IRequest::class);
		$request->method('getRemoteAddress')->willReturnCallback(fn (): string => $this->remoteAddress);
		$request->method('getHeader')->willReturnCallback(fn (string $name): string => $name === 'User-Agent' ? 'Mozilla/5.0 Firefox/140.0' : ($this->headers[$name] ?? ''));
		$request->method('getMethod')->willReturnCallback(fn (): string => $this->method);
		$request->method('getPathInfo')->willReturnCallback(fn (): string => $this->path);
		return $request;
	}

	/**
	 * One successful login in a new request, through the listener.
	 */
	protected function login(string $password = self::PASSWORD, bool $tokenLogin = false): SignalDispatcher {
		$dispatcher = $this->dispatcher([BreachedPasswordDetector::class => $this->detector()], logger: $this->logger());
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->with(SignalDispatcher::class)->willReturn($dispatcher);
		$request = $this->request();
		$listener = new BreachedPasswordListener(new InteractiveLogin($request), $request, $container, $this->logger());
		$listener->handle(new UserLoggedInEvent($this->user, $this->user->getUID(), $password, $tokenLogin));
		return $dispatcher;
	}

	protected function protect(): void {
		$this->settingsEditor()->setMode(BreachedPassword::ID, Mode::Protect);
	}

	/**
	 * @return list<Detection>
	 */
	protected function breachDetections(): array {
		return $this->detections->findList(new DetectionFilter(checkIds: [BreachedPassword::ID], limit: 10));
	}

	public function testIsOffByDefaultAndThenSendsNothing(): void {
		$this->assertSame(Mode::Off, $this->checkSettings()->configuredMode(BreachedPassword::ID));
		$this->login();
		$this->assertSame([], $this->requests, 'Off sends nothing');
		$this->assertNull($this->detector()->checkedAt($this->user));
		$this->assertSame([], $this->breachDetections());
	}

	public function testABreachedPasswordIsRecordedAndAnswered(): void {
		$this->protect();
		$this->login();

		$this->assertSame(['https://api.pwnedpasswords.com/range/21BD1'], $this->requests);
		$detector = $this->detector();
		$this->assertTrue($detector->isBreached($this->user));
		$this->assertSame($this->now, $detector->checkedAt($this->user));

		$detections = $this->breachDetections();
		$this->assertCount(1, $detections);
		$detection = $detections[0];
		$this->assertSame($this->user->getUID(), $detection->getUid());
		$this->assertSame('198.51.100.20', $detection->getIp());
		$this->assertSame('medium', $detection->getSeverity());
		$this->assertTrue($detection->isEnforced());
		$this->assertSame(['trigger' => BreachedPasswordFacts::TRIGGER_LOGIN], $detection->getExplanationData()['facts'], 'Never how often the password is listed');
		$this->assertSame(['recheck_days' => 30, 'min_count' => 1], $detection->getExplanationData()['thresholds']);
		$this->assertEqualsCanonicalizing(
			[ResponseType::StepUp->value, ResponseType::ForcePasswordChange->value, ResponseType::NotifyUser->value],
			array_map(static fn (array $a): string => $a['type'], $detection->getActionList()),
		);
	}

	public function testAPasswordBelowTheCountIsNotBreached(): void {
		$this->protect();
		$this->settingsEditor()->setParam(BreachedPassword::ID, 'min_count', 10);
		$this->listCount = 9;
		$this->login();
		$this->assertCount(1, $this->requests);
		$this->assertFalse($this->detector()->isBreached($this->user));
		$this->assertSame($this->now, $this->detector()->checkedAt($this->user), 'Checked, so not asked again for 30 days');
		$this->assertSame([], $this->breachDetections());

		$this->detector()->reset($this->user);
		$this->listCount = 10;
		$this->login();
		$this->assertTrue($this->detector()->isBreached($this->user), 'At the count, it fires');
	}

	public function testAPasswordNotOnTheListIsNotBreached(): void {
		$this->protect();
		$this->login('A-password-that-is-not-in-the-mocked-range');
		$this->assertCount(1, $this->requests);
		$this->assertFalse($this->detector()->isBreached($this->user));
		$this->assertSame([], $this->breachDetections());
	}

	public function testThePasswordIsCheckedAgainOnlyAfterTheRecheckDays(): void {
		$this->protect();
		$this->login();
		$this->now += 29 * 86400;
		$this->login();
		$this->assertCount(1, $this->requests, 'Within 30 days the password is not checked again');

		$this->now += 86400;
		$this->listCount = 0;
		$this->login();
		$this->assertCount(2, $this->requests, 'After 30 days it is');
		$this->assertFalse($this->detector()->isBreached($this->user), 'A recheck that does not find it clears the flag');
		$this->assertSame($this->now, $this->detector()->checkedAt($this->user));
	}

	public function testOneRequestChecksOnce(): void {
		$this->protect();
		$dispatcher = $this->login();
		$dispatcher->dispatch(new InteractivePasswordLogin($this->user, self::PASSWORD, null));
		$this->assertCount(1, $this->requests, 'A second caller in the same request checks nothing again');
		$this->assertCount(1, $this->breachDetections());
	}

	public function testFailsOpenAndTriesAgainAtTheNextLogin(): void {
		$this->protect();
		$this->listCount = null;
		$this->login()->dispatch(new InteractivePasswordLogin($this->user, self::PASSWORD, null));
		$this->assertCount(1, $this->requests);
		$this->assertNull($this->detector()->checkedAt($this->user), 'Nothing is stored');
		$this->assertFalse($this->detector()->isBreached($this->user));
		$this->assertSame([], $this->breachDetections());

		$this->listCount = 5;
		$this->login();
		$this->assertCount(2, $this->requests, 'The next login tries again');
		$this->assertTrue($this->detector()->isBreached($this->user));
	}

	public function testAPasswordChangeClearsTheResult(): void {
		$this->protect();
		$this->login();
		$this->assertTrue($this->detector()->isBreached($this->user));

		(new BreachResetListener($this->detector(), $this->logger()))->handle(new PasswordUpdatedEvent($this->user, 'A-new-long-password-1', null));
		$this->assertFalse($this->detector()->isBreached($this->user));
		$this->assertNull($this->detector()->checkedAt($this->user));

		$this->login('A-new-long-password-1');
		$this->assertCount(2, $this->requests, 'The new password is checked at the next login');
	}

	public function testAPasswordChangeThroughCoreReachesTheListener(): void {
		$this->protect();
		$this->login();
		$this->assertTrue($this->detector()->isBreached($this->user));
		$this->user->setPassword('A-new-long-password-2');
		$this->assertFalse($this->detector()->isBreached($this->user));
		$this->assertNull($this->detector()->checkedAt($this->user));
	}

	public function testTokenAndAppPasswordLoginsAreNeverChecked(): void {
		$this->protect();
		$this->login(tokenLogin: true);
		$this->assertSame([], $this->requests, 'App password or token login');

		$this->headers = ['Authorization' => 'Basic ' . base64_encode($this->user->getUID() . ':' . self::PASSWORD)];
		$this->setBasicCredentials($this->user->getUID(), self::PASSWORD);
		$this->method = 'PROPFIND';
		$this->path = '/files/' . $this->user->getUID();
		$this->login();
		$this->assertSame([], $this->requests, 'Basic auth with the real password');

		$this->setBasicCredentials(null, null);
		$this->method = 'POST';
		$this->path = '/login';
		$this->login();
		$this->assertCount(1, $this->requests, 'The login form is checked, whatever its headers say');
	}

	public function testAllowlistedAddressesAreNotChecked(): void {
		$this->protect();
		$this->bypassListed = true;
		$this->login();
		$this->assertSame([], $this->requests);
		$this->assertNull($this->detector()->checkedAt($this->user));
	}

	public function testObserveRecordsWithoutActing(): void {
		$this->settingsEditor()->setMode(BreachedPassword::ID, Mode::Observe);
		$this->login();
		$detections = $this->breachDetections();
		$this->assertCount(1, $detections);
		$this->assertFalse($detections[0]->isEnforced());
		foreach ($detections[0]->getActionList() as $action) {
			$this->assertFalse($action['enforced']);
		}
		$this->assertTrue($this->detector()->isBreached($this->user), 'The result is kept, so the account is not asked again');
	}

	public function testDetectionsMergePerAccountAndDay(): void {
		$this->protect();
		$this->login();
		$this->detector()->reset($this->user);
		$this->now += 3600;
		$this->login();
		$detections = $this->breachDetections();
		$this->assertCount(1, $detections);
		$this->assertSame(2, $detections[0]->getHits());
	}

	public function testTheUserCommandShowsAndResetsTheCheck(): void {
		$this->protect();
		$this->login();
		$command = Server::get(UserCommand::class);

		$output = new BufferedOutput();
		$command->run(new ArrayInput(['uid' => $this->user->getUID()]), $output);
		$this->assertStringContainsString('the current password was found on the list', $output->fetch());

		$command->run(new ArrayInput(['uid' => $this->user->getUID(), '--reset-breach-check' => true, '--output' => 'json']), $output);
		$text = $output->fetch();
		$this->assertStringContainsString('was reset', $text);
		$this->assertStringContainsString('"breach_checked_at":null,"breached":false', $text);
		$this->assertFalse($this->detector()->isBreached($this->user));
	}

	public function testTheLexiconDeclaresTheAccountValues(): void {
		$keys = [];
		foreach (Server::get(Lexicon::class)->getUserConfigs() as $entry) {
			$keys[$entry->getKey()] = $entry->isLazy();
		}
		$this->assertTrue($keys[UserKeys::BREACH_CHECKED_AT] ?? false, 'declared and lazy');
		$this->assertTrue($keys[UserKeys::BREACHED] ?? false, 'declared and lazy');
	}

	public function testExplainsItselfToAdminsAndTheUser(): void {
		$this->protect();
		$this->login();
		$detection = $this->breachDetections()[0];
		$l = Server::get(IFactory::class)->get(Application::APP_ID, 'en');

		$narrative = json_encode(Server::get(NarrativeBuilder::class)->build($detection, $l)->toArray(), JSON_THROW_ON_ERROR);
		$this->assertStringContainsString('logged in from 198.51.100.20 with a password that appears in the public list of leaked passwords', $narrative);
		$this->assertStringContainsString('only the first 5 characters of its SHA-1 hash left the server', $narrative);

		$notice = Server::get(BreachedPassword::class)->userNotice($detection, $l);
		$this->assertSame('Your password appears in lists of leaked passwords', $notice->subject);
		$this->assertStringContainsString('This has nothing to do with Nextcloud', implode(' ', $notice->message));
		$this->assertStringContainsString('attackers try the passwords on these lists first', implode(' ', $notice->message));

		$card = Server::get(CheckPresenter::class)->present(Server::get(BreachedPassword::class)->definition(), $l);
		$this->assertTrue($card['sendsData']);
		$this->assertSame('Contacts an external service. One request to api.pwnedpasswords.com per user every 30 days, during the login. It adds at most 1.5 seconds to that login, typically about 150 ms. Answers are kept in the memory cache for a day.', $card['cost']['text']);
		$this->assertStringContainsString('the first 5 characters of the SHA-1 hash of the password, for example 21BD1', $card['texts']['data']);
		$this->assertStringContainsString('The full password and its full hash never leave the server.', $card['texts']['data']);
		$this->assertSame(['days', ''], array_column($card['params'], 'unit'));
	}

	public function testNoSecretReachesAnyTableDetectionNotificationCacheOrLog(): void {
		Server::get(INotificationManager::class)->registerApp(CapturingNotificationApp::class);
		CapturingNotificationApp::$notifications = [];
		$logFile = $this->logFile();
		$logOffset = is_file($logFile) ? (int)filesize($logFile) : 0;
		$cache = new class extends ArrayCache {
			/** @return array<string, mixed> */
			public function all(): array {
				return $this->cachedData;
			}
		};
		$this->cache = $cache;
		$this->protect();
		$this->settingsEditor()->setResponses(BreachedPassword::ID, [ResponseType::StepUp, ResponseType::ForcePasswordChange, ResponseType::NotifyAdmin, ResponseType::NotifyUser]);

		// SHA-1 EDB0E576C4E745D575F45B5DD8DD1EF7F6070FA0
		$password = 'Secret-Breached-Password-7e3b';
		$hash = strtoupper(sha1($password));
		$prefix = substr($hash, 0, 5);
		$this->suffix = substr($hash, 5);
		$this->assertSame('EDB0E', $prefix);

		$this->login($password);
		$this->assertTrue($this->detector()->isBreached($this->user));
		// A failed check: the client's exception names the address with the prefix.
		$this->detector()->reset($this->user);
		$this->listCount = null;
		$this->cache = null;
		$this->login($password);
		$this->assertNotSame([], $this->logged, 'The failure was logged');

		$secrets = [$password, $hash, strtolower($hash), $this->suffix, strtolower($this->suffix)];
		$secretsAndPrefix = array_merge($secrets, [$prefix, strtolower($prefix), '/range/' . $prefix]);

		// Tables: the app's own and its per-account values. Hex columns
		// (merge keys) are lower-case, so the prefix is looked for as sent.
		$tables = IntegrationTestCase::tables();
		$rows = [];
		foreach ($tables as $table) {
			$result = $this->db->getQueryBuilder()->select('*')->from($table)->executeQuery();
			$rows[$table] = $result->fetchAll();
			$result->closeCursor();
		}
		$qb = $this->db->getQueryBuilder();
		$result = $qb->select('*')->from('preferences')->where($qb->expr()->eq('appid', $qb->createNamedParameter(Application::APP_ID)))->executeQuery();
		$rows['preferences'] = $result->fetchAll();
		$result->closeCursor();
		$this->assertNotSame([], $rows['ids_detections']);
		foreach ($rows as $table => $tableRows) {
			$this->assertClean(json_encode($tableRows, JSON_THROW_ON_ERROR), array_merge($secrets, [$prefix]), $table);
		}

		// Detections as explained, notified and mailed
		$l = Server::get(IFactory::class)->get(Application::APP_ID, 'en');
		$admin = $this->createMock(IUser::class);
		$admin->method('getUID')->willReturn('admin');
		$admin->method('getEMailAddress')->willReturn('admin@example.com');
		foreach ($this->breachDetections() as $detection) {
			$this->assertClean(json_encode($detection->getExplanationData()) . json_encode($detection->getActionList()), $secretsAndPrefix, 'detection');
			$this->assertClean(json_encode(Server::get(NarrativeBuilder::class)->build($detection, $l)->toArray()), $secretsAndPrefix, 'narrative');
			$notice = Server::get(BreachedPassword::class)->userNotice($detection, $l);
			$this->assertClean($notice->subject . implode(' ', $notice->message), $secretsAndPrefix, 'user notice');
			$mail = Server::get(AdminAlerts::class)->mailFor($detection, $admin);
			$this->assertClean(json_encode(get_object_vars($mail)), $secretsAndPrefix, 'admin email');
		}
		$this->assertNotSame([], CapturingNotificationApp::$notifications, 'The admins were notified');
		foreach (CapturingNotificationApp::$notifications as $notification) {
			$prepared = Server::get(Notifier::class)->prepare($notification, 'en');
			$this->assertClean(json_encode($notification->getSubjectParameters()) . $prepared->getParsedSubject() . $prepared->getParsedMessage() . $prepared->getLink(), $secretsAndPrefix, 'notification');
		}

		// The memory cache holds the range under a keyed name, encrypted.
		$this->assertNotSame([], $cache->all());
		$this->assertClean(json_encode($cache->all(), JSON_THROW_ON_ERROR), array_merge($secrets, [$prefix]), 'memory cache');

		// Logs
		$this->assertClean(implode("\n", $this->logged), $secretsAndPrefix, 'app log');
		$this->assertClean(is_file($logFile) ? (string)file_get_contents($logFile, false, null, $logOffset) : '', $secretsAndPrefix, 'server log');
	}

	/**
	 * @param list<string> $secrets
	 */
	private function assertClean(string $text, array $secrets, string $where): void {
		foreach ($secrets as $secret) {
			$this->assertStringNotContainsString($secret, $text, 'A secret (' . strlen($secret) . ' characters) is in the ' . $where);
		}
	}

	private function logFile(): string {
		$config = Server::get(IConfig::class);
		return $config->getSystemValueString('logfile', $config->getSystemValueString('datadirectory', \OC::$SERVERROOT . '/data') . '/nextcloud.log');
	}
}
