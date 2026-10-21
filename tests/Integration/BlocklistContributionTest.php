<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\BackgroundJob\ContributionJob;
use OCA\IntrusionDetection\Blocklist\BlocklistContribution;
use OCA\IntrusionDetection\Blocklist\ContributionBatch;
use OCA\IntrusionDetection\Blocklist\ContributionOverview;
use OCA\IntrusionDetection\Blocklist\ContributionSettings;
use OCA\IntrusionDetection\Blocklist\ContributionState;
use OCA\IntrusionDetection\Blocklist\LimitedSink;
use OCA\IntrusionDetection\Blocklist\SyncFailure;
use OCA\IntrusionDetection\Blocklist\UrlPolicy;
use OCA\IntrusionDetection\Check\Checks\DecoyCredential;
use OCA\IntrusionDetection\Check\Checks\ReservedName;
use OCA\IntrusionDetection\Check\Checks\TrapUrl;
use OCA\IntrusionDetection\Check\InvalidParamException;
use OCA\IntrusionDetection\Command\Contribution\Preview;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\Ban;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\BackgroundJob\IJobList;
use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\Http\Client\IClient;
use OCP\Http\Client\IClientService;
use OCP\Http\Client\IResponse;
use OCP\IConfig;
use OCP\IL10N;
use OCP\L10N\IFactory;
use OCP\Log\Audit\CriticalActionPerformedEvent;
use OCP\Security\Bruteforce\IThrottler;
use OCP\Security\ISecureRandom;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\AbstractLogger;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * The shared blocklist contribution, with a mocked HTTP client: nothing here
 * contacts the internet.
 */
#[Group('DB')]
class BlocklistContributionTest extends IntegrationTestCase {
	private const URL = 'https://blocklist.example.org/v1/reports';

	private int $now = 1792490400;
	private bool $available = true;
	/** @var list<string> */
	private array $bypass = [];
	/** @var list<int|\Throwable> status codes or exceptions, in order */
	private array $responses = [];
	/** @var list<array{url: string, options: array<string, mixed>}> */
	private array $requests = [];
	/** @var list<string> */
	private array $logLines = [];
	/** @var list<string> */
	private array $auditLines = [];
	private int $references = 0;
	private Settings $settings;

	protected function setUp(): void {
		parent::setUp();
		$this->settings = Server::get(Settings::class);
	}

	public function testNothingHappensAndNothingIsShownUnlessConfigPhpMakesItAvailable(): void {
		$this->available = false;
		$this->appConfig->setValueBool(Application::APP_ID, GlobalSettings::CONTRIBUTE_ENABLED, true);
		$this->appConfig->setValueString(Application::APP_ID, GlobalSettings::CONTRIBUTE_URL, self::URL);
		$this->block('198.51.100.7/32', TrapUrl::ID, $this->now - 3600);

		$this->job()->start($this->createMock(IJobList::class));
		$batch = $this->contribution()->send();

		$this->assertSame([], $this->requests, 'Nothing is sent');
		$this->assertSame(ContributionBatch::REASON_UNAVAILABLE, $batch->reason);
		$this->assertNull($batch->payload);
		$this->assertSame('', $batch->body());
		$this->assertNull($this->contribution()->preview()->payload);
		$this->assertNull($this->overview()->get($this->l()), 'The admin page gets nothing to show');
		$this->assertFalse($this->config()->isEnabled());
		$this->assertFalse($this->appConfig->hasKey(Application::APP_ID, GlobalSettings::CONTRIBUTE_STATE), 'No run is recorded');
		$this->assertFalse($this->appConfig->hasKey(Application::APP_ID, GlobalSettings::CONTRIBUTE_ID), 'No contributor id is generated');
		$placeholders = $this->settings->placeholderValues();
		foreach ([GlobalSettings::CONTRIBUTE_ENABLED, GlobalSettings::CONTRIBUTE_URL, GlobalSettings::CONTRIBUTE_ID, GlobalSettings::CONTRIBUTE_STATE] as $key) {
			$this->assertArrayNotHasKey($key, $placeholders, $key . ' is not listed');
		}
		foreach ([fn () => $this->config()->setEnabled(true, 'admin'), fn () => $this->config()->setUrl(self::URL, 'admin')] as $set) {
			try {
				$set();
				$this->fail('The setting cannot be changed while hidden');
			} catch (InvalidParamException $e) {
				$this->assertSame('contribution_unavailable', $e->reason);
			}
		}

		$tester = new CommandTester($this->command());
		$this->assertSame(Command::SUCCESS, $tester->execute([]));
		$this->assertSame("Contributing to a shared blocklist is not available on this server.\n", $tester->getDisplay());
	}

	public function testTheJobDoesNothingUntilTheAdminSwitchesItOn(): void {
		$this->enable(false);
		$this->block('198.51.100.7/32', TrapUrl::ID, $this->now - 3600);

		$this->job()->start($this->createMock(IJobList::class));

		$this->assertSame([], $this->requests);
		$this->assertSame(ContributionBatch::REASON_DISABLED, $this->contribution()->preview()->reason);
		$this->assertSame('198.51.100.7', $this->contribution()->preview()->payload['reports'][0]['ip'] ?? null, 'The preview still shows what would be sent');
	}

	public function testTheJobSendsOnceSwitchedOn(): void {
		$this->enable();
		$this->block('198.51.100.7/32', TrapUrl::ID, $this->now - 3600);
		$this->responses = [202];

		$job = $this->job();
		$this->assertSame(86400, $job->getInterval());
		$job->start($this->createMock(IJobList::class));

		$this->assertCount(1, $this->requests);
		$this->assertSame(ContributionState::RESULT_SENT, $this->config()->state()->result);
	}

	public function testOnlyEnforcedBlocksOfTheThreeTrapChecksAreReported(): void {
		$this->enable();
		$at = $this->now - 3600;
		$this->block('198.51.100.1/32', DecoyCredential::ID, $at);
		$this->block('198.51.100.2/32', TrapUrl::ID, $at);
		$this->block('198.51.100.3/32', ReservedName::ID, $at);
		$this->block('2001:db8:1:2::/64', TrapUrl::ID, $at, scope: Ban::SCOPE_NET, ip: '2001:db8:1:2::7');
		$this->block('198.51.100.10/32', 'credential_stuffing', $at);
		$this->block('198.51.100.11/32', 'password_spraying', $at);
		$this->block('198.51.100.12/32', TrapUrl::ID, $at, enforced: false);
		$this->block('198.51.100.13/32', ReservedName::ID, $at, lifted: true);
		$this->block('198.51.100.14/32', 'manual', $at, detection: false);
		$this->block('198.51.100.15/32', TrapUrl::ID, $at, detection: false);
		$this->block('198.51.100.0/24', TrapUrl::ID, $at, scope: Ban::SCOPE_NET);

		$reports = $this->contribution()->preview()->payload['reports'] ?? [];

		$this->assertSame([
			'198.51.100.1' => DecoyCredential::ID,
			'198.51.100.2' => TrapUrl::ID,
			'198.51.100.3' => ReservedName::ID,
			'2001:db8:1:2::/64' => TrapUrl::ID,
		], array_column($reports, 'check', 'ip'));
	}

	public function testPrivateReservedAndAllowlistedAddressesNeverLeaveTheServer(): void {
		$this->enable();
		$at = $this->now - 3600;
		foreach (['10.1.2.3/32', '172.16.5.4/32', '192.168.1.1/32', '127.0.0.1/32', '169.254.1.1/32', '100.64.0.9/32', '0.0.0.1/32', '240.0.0.1/32'] as $cidr) {
			$this->block($cidr, TrapUrl::ID, $at);
		}
		foreach (['fc00:1:2:3::/64', 'fd12:3456:789a:1::/64', 'fe80::/64'] as $cidr) {
			$this->block($cidr, TrapUrl::ID, $at, scope: Ban::SCOPE_NET);
		}
		$this->bypass = ['198.51.100.20', '2001:db8:9:9::5'];
		$this->block('198.51.100.20/32', DecoyCredential::ID, $at);
		$this->block('2001:db8:9:9::/64', TrapUrl::ID, $at, scope: Ban::SCOPE_NET, ip: '2001:db8:9:9::5');
		$this->block('198.51.100.21/32', DecoyCredential::ID, $at);

		$reports = $this->contribution()->preview()->payload['reports'] ?? [];

		$this->assertSame(['198.51.100.21'], array_column($reports, 'ip'));
	}

	public function testAtMostAThousandAddressesAreSentPerRun(): void {
		$this->enable();
		$this->db->beginTransaction();
		for ($i = 0; $i < BlocklistContribution::MAX_REPORTS + 5; $i++) {
			$this->block('203.0.' . intdiv($i, 250) . '.' . ($i % 250 + 1) . '/32', TrapUrl::ID, $this->now - 7200 + $i);
		}
		$this->db->commit();
		$this->responses = [202];

		$preview = $this->contribution()->preview();
		$this->assertCount(BlocklistContribution::MAX_REPORTS, $preview->payload['reports'] ?? []);
		$this->assertTrue($preview->truncated);
		$this->assertSame('203.0.0.1', $preview->payload['reports'][0]['ip'] ?? null, 'The oldest come first');

		$this->contribution()->send();
		$sent = json_decode($this->requests[0]['options']['body'], true);
		$this->assertCount(BlocklistContribution::MAX_REPORTS, $sent['reports']);
	}

	public function testTheWindowOnlyMovesOnAfterASuccessfulSend(): void {
		$this->enable();
		$this->block('198.51.100.7/32', TrapUrl::ID, $this->now - 3600);
		$this->responses = [500, new \RuntimeException('Connection refused'), 202, 202];
		$firstStart = $this->now - BlocklistContribution::FIRST_WINDOW;

		$this->contribution()->send();
		$state = $this->config()->state();
		$this->assertSame(ContributionState::RESULT_FAILED, $state->result);
		$this->assertSame('http_500', $state->error);
		$this->assertSame($firstStart, $state->windowEnd, 'The first window is fixed, not moved on');
		$this->assertNull($state->successAt);

		$this->now += 86400;
		$this->block('198.51.100.8/32', DecoyCredential::ID, $this->now - 600);
		$this->contribution()->send();
		$this->assertSame('network', $this->config()->state()->error);
		$this->assertSame($firstStart, $this->config()->state()->windowEnd);

		$this->now += 86400;
		$this->block('198.51.100.9/32', ReservedName::ID, $this->now - 600);
		$this->contribution()->send();
		$state = $this->config()->state();
		$this->assertSame(ContributionState::RESULT_SENT, $state->result);
		$this->assertNull($state->error);
		$this->assertSame($this->now, $state->windowEnd);
		$this->assertSame($this->now, $state->successAt);
		$this->assertSame(3, $state->reports);
		$this->assertSame(['198.51.100.7', '198.51.100.8', '198.51.100.9'], $this->sentIps(2), 'Everything since the last success is sent');
		$this->assertContains('Intrusion detection: shared blocklist contribution sent %s reports to %s', $this->auditLines);

		$this->now += 86400;
		$this->block('198.51.100.30/32', TrapUrl::ID, $this->now - 600);
		$this->contribution()->send();
		$this->assertSame(['198.51.100.30'], $this->sentIps(3), 'Reports already sent are not sent again');

		$this->now += 86400;
		$batch = $this->contribution()->send();
		$this->assertSame(ContributionBatch::REASON_NOTHING_NEW, $batch->reason);
		$this->assertCount(4, $this->requests, 'Nothing new: nothing is sent');
		$this->assertSame(ContributionState::RESULT_NOTHING, $this->config()->state()->result);
		$this->assertSame($this->now, $this->config()->state()->windowEnd);
	}

	public function testTheFirstWindowIsOneDayAndNoWindowReachesFurtherBackThanAWeek(): void {
		$this->enable();
		$this->block('198.51.100.1/32', TrapUrl::ID, $this->now - 86400 - 60);
		$this->block('198.51.100.2/32', TrapUrl::ID, $this->now - 86400 + 60);
		$this->assertSame(['198.51.100.2'], array_column($this->contribution()->preview()->payload['reports'] ?? [], 'ip'));

		$this->config()->saveState(new ContributionState(windowEnd: $this->now - 30 * 86400));
		$this->block('198.51.100.3/32', TrapUrl::ID, $this->now - 8 * 86400);
		$batch = $this->contribution()->preview();
		$this->assertSame($this->now - BlocklistContribution::MAX_WINDOW, $batch->windowStart);
		$this->assertSame(['198.51.100.1', '198.51.100.2'], array_column($batch->payload['reports'] ?? [], 'ip'));
	}

	public function testThePayloadHasExactlyTheDocumentedShape(): void {
		$this->enable();
		$first = $this->now - 5000;
		$this->block('198.51.100.7/32', TrapUrl::ID, $this->now - 4000, hits: 3, firstSeen: $first);
		// The same address blocked again later by the same check: one report.
		$this->block('198.51.100.7/32', TrapUrl::ID, $this->now - 1000, hits: 2, firstSeen: $this->now - 1200);
		$this->block('198.51.100.7/32', DecoyCredential::ID, $this->now - 900, hits: 1, firstSeen: $this->now - 900);
		$this->responses = [202];

		$preview = $this->contribution()->preview();
		$this->contribution()->send();

		$instance = $this->appConfig->getValueString(Application::APP_ID, GlobalSettings::CONTRIBUTE_ID);
		$expected = [
			'instance' => $instance,
			'version' => BlocklistContribution::FORMAT_VERSION,
			'reports' => [
				['ip' => '198.51.100.7', 'check' => TrapUrl::ID, 'first_seen' => $first, 'hits' => 5],
				['ip' => '198.51.100.7', 'check' => DecoyCredential::ID, 'first_seen' => $this->now - 900, 'hits' => 1],
			],
		];
		$this->assertSame($expected, $preview->payload);
		$this->assertSame(json_encode($expected, JSON_UNESCAPED_SLASHES), $this->requests[0]['options']['body'], 'The preview is exactly what is sent');
		$this->assertSame(self::URL, $this->requests[0]['url']);
		$this->assertMatchesRegularExpression('/^[a-z0-9]{32}$/', $instance);
		$this->assertNotSame(Server::get(IConfig::class)->getSystemValueString('instanceid'), $instance);
		$this->assertStringNotContainsString(Server::get(IConfig::class)->getSystemValueString('instanceid'), $this->requests[0]['options']['body']);
	}

	public function testTheContributorIdIsRandomAndGeneratedOnce(): void {
		$this->enable();
		$random = $this->createMock(ISecureRandom::class);
		$random->expects($this->once())->method('generate')
			->with(ContributionSettings::ID_LENGTH, ISecureRandom::CHAR_LOWER . ISecureRandom::CHAR_DIGITS)
			->willReturn(str_repeat('a1', 16));
		$config = $this->config($random);

		$this->assertSame(str_repeat('a1', 16), $config->contributorId());
		$this->assertSame(str_repeat('a1', 16), $config->contributorId());
		$this->assertSame(str_repeat('a1', 16), $this->config()->contributorId(), 'Stored, not generated again');
	}

	public function testNoSecretOrUserDataLeavesTheServer(): void {
		$this->enable();
		$secrets = ['alice', 'Mozilla/5.0 SecretAgent', 'wiki-backup-decoy', 'DECOY-SECRET-1234', '/.env', 'K7Q2MPXA'];
		$this->block('198.51.100.7/32', DecoyCredential::ID, $this->now - 600, uid: 'alice', explanation: [
			'loginName' => 'alice',
			'userAgent' => 'Mozilla/5.0 SecretAgent',
			'label' => 'wiki-backup-decoy',
			'secret' => 'DECOY-SECRET-1234',
			'path' => '/.env',
		], reference: 'K7Q2MPXA');
		$this->responses = [202, 500];

		$this->contribution()->send();
		$this->now += 86400;
		$this->block('198.51.100.8/32', DecoyCredential::ID, $this->now - 600, uid: 'alice', explanation: ['userAgent' => 'Mozilla/5.0 SecretAgent']);
		$this->contribution()->send();

		$body = $this->requests[0]['options']['body'];
		$this->assertSame(['instance', 'version', 'reports'], array_keys(json_decode($body, true)));
		$this->assertSame(['ip', 'check', 'first_seen', 'hits'], array_keys(json_decode($body, true)['reports'][0]));
		$recorded = implode("\n", array_merge(
			[$body, json_encode($this->requests[0]['options']['headers'])],
			$this->logLines,
			$this->auditLines,
			[$this->appConfig->getValueString(Application::APP_ID, GlobalSettings::CONTRIBUTE_STATE)],
		));
		foreach ($secrets as $secret) {
			$this->assertStringNotContainsString($secret, $recorded);
		}
	}

	public function testTheRequestIsBoundedAndFollowsNoRedirect(): void {
		$this->enable();
		$this->block('198.51.100.7/32', TrapUrl::ID, $this->now - 600);
		$this->responses = [202];

		$this->contribution()->send();

		$options = $this->requests[0]['options'];
		$this->assertFalse($options['allow_redirects']);
		$this->assertLessThanOrEqual(30, $options['timeout']);
		$this->assertLessThanOrEqual(10, $options['connect_timeout']);
		$this->assertSame('application/json', $options['headers']['Content-Type']);
		$this->assertArrayNotHasKey('nextcloud', $options, 'Local addresses stay forbidden');
		$this->assertInstanceOf(LimitedSink::class, $options['sink']);
		$options['sink']->write(str_repeat('a', BlocklistContribution::MAX_RESPONSE_BYTES));
		try {
			$options['sink']->write('a');
			$this->fail('The answer is limited');
		} catch (SyncFailure $e) {
			$this->assertSame(SyncFailure::TOO_LARGE, $e->reason);
		}
	}

	public function testAnAnswerAboveTheLimitCountsAsAFailure(): void {
		$this->enable();
		$this->block('198.51.100.7/32', TrapUrl::ID, $this->now - 600);
		$this->responses = [new \RuntimeException('aborted', 0, new SyncFailure(SyncFailure::TOO_LARGE))];

		$this->contribution()->send();

		$this->assertSame('response_too_large', $this->config()->state()->error);
		$this->assertSame($this->now - BlocklistContribution::FIRST_WINDOW, $this->config()->state()->windowEnd);
	}

	public function testOnlyHttpsAddressesOutsideTheLocalNetworkAreAccepted(): void {
		$this->enable();
		foreach (['http://blocklist.example.org/v1', 'https://user:pw@blocklist.example.org/v1', 'https://127.0.0.1/v1', 'https://localhost/v1', 'https://192.168.1.5/v1', 'ftp://blocklist.example.org/'] as $url) {
			try {
				$this->config()->setUrl($url, 'admin');
				$this->fail($url . ' must be refused');
			} catch (InvalidParamException $e) {
				$this->assertSame('contribution_url_refused', $e->reason);
			}
		}
		$this->config()->setUrl(' ' . self::URL . ' ', 'admin');
		$this->assertSame(self::URL, $this->config()->url());
		$this->assertContains('Intrusion detection: shared blocklist contribution address set to %s by %s', $this->auditLines);
		$this->config()->setUrl('', 'admin');
		$this->assertSame('', $this->config()->url());
	}

	public function testAnAddressThatBecameInvalidIsNotUsed(): void {
		$this->enable();
		$this->block('198.51.100.7/32', TrapUrl::ID, $this->now - 600);
		// Set past the validation, as `occ config:app:set` would.
		$this->appConfig->setValueString(Application::APP_ID, GlobalSettings::CONTRIBUTE_URL, 'https://127.0.0.1/v1');

		$batch = $this->contribution()->send();

		$this->assertSame(ContributionBatch::REASON_URL_REFUSED, $batch->reason);
		$this->assertSame([], $this->requests);
		$this->assertSame('url_refused', $this->config()->state()->error);

		$this->appConfig->setValueString(Application::APP_ID, GlobalSettings::CONTRIBUTE_URL, '');
		$this->assertSame(ContributionBatch::REASON_NO_URL, $this->contribution()->send()->reason);
		$this->assertSame([], $this->requests);
	}

	public function testNothingIsSentWhileIntrusionDetectionIsOff(): void {
		$this->enable();
		$this->block('198.51.100.7/32', TrapUrl::ID, $this->now - 600);
		$this->settings->setGlobal(GlobalSettings::ENABLED, false);

		$this->assertSame(ContributionBatch::REASON_PROTECTION_OFF, $this->contribution()->send()->reason);
		$this->assertSame([], $this->requests);
	}

	public function testTheAdminPageGetsTheSettingsTextsAndTheLivePreview(): void {
		$this->enable();
		$this->block('198.51.100.7/32', TrapUrl::ID, $this->now - 600);

		$view = $this->overview()->get($this->l());

		$this->assertNotNull($view);
		$this->assertTrue($view['enabled']);
		$this->assertSame(self::URL, $view['url']);
		$this->assertNull($view['preview']['reason']);
		$this->assertSame($this->contribution()->preview()->payload, $view['preview']['payload']);
		$this->assertStringContainsString('GDPR', $view['texts']['privacy']);
		$this->assertStringContainsString('legal basis', $view['texts']['privacy']);
		foreach ($view['texts'] as $field => $text) {
			$this->assertNotSame('', trim($text), $field);
		}
	}

	public function testOccPrintsTheExactNextPayload(): void {
		$this->enable(false);
		$this->block('198.51.100.7/32', TrapUrl::ID, $this->now - 600);

		$tester = new CommandTester($this->command());
		$this->assertSame(Command::SUCCESS, $tester->execute([]));
		$lines = explode("\n", trim($tester->getDisplay()));

		$this->assertStringStartsWith('Contributing is off', $lines[0]);
		$this->assertStringContainsString(self::URL, $lines[1]);
		$this->assertSame($this->contribution()->preview()->body(), end($lines));

		$this->assertSame(Command::SUCCESS, $tester->execute(['--output' => 'json']));
		$json = json_decode($tester->getDisplay(), true);
		$this->assertSame(ContributionBatch::REASON_DISABLED, $json['reason']);
		$this->assertSame($this->contribution()->preview()->payload, $json['payload']);
	}

	/**
	 * Insert a ban and, unless told otherwise, the detection behind it.
	 *
	 * @param array<string, mixed> $explanation
	 */
	private function block(
		string $cidr,
		string $check,
		int $createdAt,
		bool $enforced = true,
		int $hits = 1,
		?int $firstSeen = null,
		?string $ip = null,
		bool $lifted = false,
		string $scope = Ban::SCOPE_IP,
		bool $detection = true,
		?string $uid = null,
		array $explanation = [],
		?string $reference = null,
	): void {
		$detectionId = null;
		if ($detection) {
			$row = new Detection();
			$row->setCheckId($check);
			$row->setSeverity('high');
			$row->setEnforced($enforced);
			$row->setIp($ip ?? explode('/', $cidr)[0]);
			$row->setUid($uid);
			$row->setExplanationData($explanation);
			$row->setActionList([]);
			$row->setCreatedAt($firstSeen ?? $createdAt);
			$row->setLastSeenAt($createdAt);
			$row->setHits($hits);
			$detectionId = Server::get(DetectionMapper::class)->insert($row)->getId();
		}
		$ban = new Ban();
		$ban->setReference($reference ?? sprintf('T%07d', ++$this->references));
		$ban->setCidr($cidr);
		$ban->setScope($scope);
		$ban->setBanKey($scope === Ban::SCOPE_IP ? explode('/', $cidr)[0] : $cidr);
		$ban->setLevel(1);
		$ban->setCheckId($check);
		$ban->setDetectionId($detectionId);
		$ban->setCreatedAt($createdAt);
		$ban->setExpiresAt($createdAt + 14400);
		if ($lifted) {
			$ban->setLiftedAt($createdAt + 60);
			$ban->setLiftedBy('admin');
		}
		Server::get(BanMapper::class)->insert($ban);
	}

	private function enable(bool $enabled = true): void {
		$this->config()->setUrl(self::URL, 'admin');
		$this->config()->setEnabled($enabled, 'admin');
	}

	/**
	 * @return list<string> the addresses of the given request
	 */
	private function sentIps(int $request): array {
		return array_column(json_decode($this->requests[$request]['options']['body'], true)['reports'], 'ip');
	}

	private function config(?ISecureRandom $random = null): ContributionSettings {
		$system = $this->createMock(IConfig::class);
		$system->method('getSystemValueBool')->willReturnCallback(
			fn (string $key, bool $default): bool => $key === ContributionSettings::SYSTEM_KEY ? $this->available : $default,
		);
		return new ContributionSettings($system, $this->settings, Server::get(UrlPolicy::class), $random ?? Server::get(ISecureRandom::class), $this->audit());
	}

	private function contribution(): BlocklistContribution {
		$throttler = $this->createMock(IThrottler::class);
		$throttler->method('isBypassListed')->willReturnCallback(fn (string $ip): bool => in_array($ip, $this->bypass, true));

		$client = $this->createMock(IClient::class);
		$client->method('get')->willThrowException(new \LogicException('Only POST is expected'));
		$client->method('post')->willReturnCallback(function (string $url, array $options): IResponse {
			$this->requests[] = ['url' => $url, 'options' => $options];
			$next = array_shift($this->responses) ?? throw new \LogicException('No response prepared');
			if ($next instanceof \Throwable) {
				throw $next;
			}
			$response = $this->createMock(IResponse::class);
			$response->method('getStatusCode')->willReturn($next);
			return $response;
		});
		$clientService = $this->createMock(IClientService::class);
		$clientService->method('newClient')->willReturn($client);

		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturnCallback(fn (): int => $this->now);

		$logger = new class(function (string $line): void {
			$this->logLines[] = $line;
		}) extends AbstractLogger {
			public function __construct(
				private readonly \Closure $sink,
			) {
			}

			public function log($level, string|\Stringable $message, array $context = []): void {
				$exception = $context['exception'] ?? null;
				unset($context['exception']);
				($this->sink)($level . ' ' . $message . ' ' . json_encode($context) . ($exception instanceof \Throwable ? ' ' . $exception->getMessage() : ''));
			}
		};

		return new BlocklistContribution(
			$this->config(),
			$this->settings,
			Server::get(BanMapper::class),
			$throttler,
			$clientService,
			Server::get(UrlPolicy::class),
			$this->audit(),
			$time,
			$logger,
		);
	}

	private function job(): ContributionJob {
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturnCallback(fn (): int => $this->now);
		return new ContributionJob($time, $this->config(), $this->contribution());
	}

	private function overview(): ContributionOverview {
		return new ContributionOverview($this->config(), $this->contribution());
	}

	private function command(): Preview {
		return new Preview($this->contribution(), $this->config(), $this->l());
	}

	private function audit(): AuditLogger {
		$dispatcher = $this->createMock(IEventDispatcher::class);
		$dispatcher->method('dispatchTyped')->willReturnCallback(function (Event $event): void {
			if ($event instanceof CriticalActionPerformedEvent) {
				$this->auditLines[] = $event->getLogMessage();
				$this->auditLines[] = implode(' ', $event->getParameters());
			}
		});
		return new AuditLogger($dispatcher);
	}

	private function l(): IL10N {
		return Server::get(IFactory::class)->get(Application::APP_ID, 'en');
	}
}
