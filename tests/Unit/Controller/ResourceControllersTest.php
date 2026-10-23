<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Controller;

use OCA\IntrusionDetection\Admin\BanPresenter;
use OCA\IntrusionDetection\Admin\CheckList;
use OCA\IntrusionDetection\Admin\DailyStats;
use OCA\IntrusionDetection\Admin\DetectionPresenter;
use OCA\IntrusionDetection\Admin\GlobalSettingsPresenter;
use OCA\IntrusionDetection\Admin\LookupService;
use OCA\IntrusionDetection\Admin\SettingsTransfer;
use OCA\IntrusionDetection\Admin\StatusService;
use OCA\IntrusionDetection\AdminChange\ActorResolver;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Configure\ProtectionLevels;
use OCA\IntrusionDetection\Configure\SettingsEditor;
use OCA\IntrusionDetection\Controller\BanApiController;
use OCA\IntrusionDetection\Controller\CheckApiController;
use OCA\IntrusionDetection\Controller\DetectionApiController;
use OCA\IntrusionDetection\Controller\SettingsApiController;
use OCA\IntrusionDetection\Db\Ban;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Definition\Category;
use OCA\IntrusionDetection\Definition\CheckDefinition;
use OCA\IntrusionDetection\Definition\CheckTexts;
use OCA\IntrusionDetection\Definition\CostClass;
use OCA\IntrusionDetection\Definition\InvalidParamException;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\ParamDefinition;
use OCA\IntrusionDetection\Definition\ParamType;
use OCA\IntrusionDetection\Definition\ProtectionLevel;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Definition\Severity;
use OCA\IntrusionDetection\Learning\LearningService;
use OCA\IntrusionDetection\Net\RemoteAddressResolver;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\BanRefusedException;
use OCA\IntrusionDetection\Response\BanService;
use OCP\AppFramework\Db\DoesNotExistException;
use OCP\AppFramework\Http;
use OCP\AppFramework\OCS\OCSNotFoundException;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IL10N;
use OCP\IRequest;
use OCP\IUser;
use OCP\IUserSession;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\MockObject\MockObject;
use Test\TestCase;

/**
 * The admin page's resource controllers: checks, detections, blocks and settings.
 */
class ResourceControllersTest extends TestCase {
	use AnswersLikeTheApi;

	private const CHECK = 'test_check';

	private CheckRegistry&MockObject $registry;
	private SettingsEditor&MockObject $settings;
	private CheckList&MockObject $checks;
	private DetectionMapper&MockObject $detectionMapper;
	private DetectionPresenter&MockObject $detections;
	private BanMapper&MockObject $banMapper;
	private BanService&MockObject $banService;
	private BanPresenter&MockObject $bans;
	private LearningService&MockObject $learning;
	private GlobalSettingsPresenter&MockObject $globalSettings;
	private SettingsTransfer&MockObject $transfer;
	private RemoteAddressResolver&MockObject $addresses;
	private AuditLogger&MockObject $audit;
	private ProtectionLevels&MockObject $levels;
	private StatusService&MockObject $status;
	private CheckDefinition $check;
	private CheckApiController $checkApi;
	private DetectionApiController $detectionApi;
	private BanApiController $banApi;
	private SettingsApiController $settingsApi;

	protected function setUp(): void {
		parent::setUp();
		$l = Server::get(IFactory::class)->get('intrusion_detection', 'en');
		$user = $this->createMock(IUser::class);
		$user->method('getUID')->willReturn('alice');
		$session = $this->createMock(IUserSession::class);
		$session->method('getUser')->willReturn($user);
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturn(1_790_000_000);

		$this->check = self::definition(self::CHECK);
		$internal = self::definition('internal_one', internal: true);
		$this->registry = $this->createMock(CheckRegistry::class);
		$this->registry->method('has')->willReturnCallback(fn (string $id): bool => in_array($id, [self::CHECK, 'internal_one'], true));
		$this->registry->method('get')->willReturnCallback(fn (string $id): CheckDefinition => match ($id) {
			self::CHECK => $this->check,
			'internal_one' => $internal,
			default => throw new InvalidParamException('unknown_check', ['check' => $id]),
		});

		$this->settings = $this->createMock(SettingsEditor::class);
		$this->status = $this->createMock(StatusService::class);
		$this->checks = $this->createMock(CheckList::class);
		$this->checks->method('one')->willReturn(['id' => self::CHECK]);
		$this->detectionMapper = $this->createMock(DetectionMapper::class);
		$this->detections = $this->createMock(DetectionPresenter::class);
		$this->banMapper = $this->createMock(BanMapper::class);
		$this->banService = $this->createMock(BanService::class);
		$this->bans = $this->createMock(BanPresenter::class);
		$this->bans->method('present')->willReturn(['id' => 1]);
		$this->learning = $this->createMock(LearningService::class);
		$this->globalSettings = $this->createMock(GlobalSettingsPresenter::class);
		$this->globalSettings->method('isEditable')->willReturnCallback(static fn (string $name): bool => $name !== GlobalSettings::LEARNING_UNTIL);
		$this->globalSettings->method('present')->willReturn(['settings' => [], 'templates' => []]);
		$this->transfer = $this->createMock(SettingsTransfer::class);
		$this->addresses = $this->createMock(RemoteAddressResolver::class);
		$this->addresses->method('current')->willReturn(SourceKey::fromIp('192.0.2.10'));
		$this->audit = $this->createMock(AuditLogger::class);
		$this->levels = $this->createMock(ProtectionLevels::class);

		$actors = new ActorResolver($session);
		$request = $this->createMock(IRequest::class);
		$this->checkApi = new CheckApiController($request, $l, $actors, $this->registry, $this->settings, $this->status, $this->checks, $this->levels, $this->audit);
		$this->detectionApi = new DetectionApiController($request, $l, $actors, $this->detectionMapper, $this->detections, $this->createMock(DailyStats::class), $this->createMock(LookupService::class));
		$this->banApi = new BanApiController($request, $l, $actors, $time, $this->banMapper, $this->banService, $this->bans, $this->addresses, $this->audit);
		$this->settingsApi = new SettingsApiController($request, $l, $actors, $this->status, $this->settings, $this->learning, $this->globalSettings, new GlobalSettings(), $this->transfer, $this->audit);
	}

	private static function definition(string $id, bool $internal = false): CheckDefinition {
		return new CheckDefinition(
			id: $id,
			category: Category::LoginAttacks,
			defaultMode: Mode::Protect,
			severity: Severity::Medium,
			params: [
				new ParamDefinition('window', ParamType::Duration, 600, min: 60, max: 3600),
				new ParamDefinition('min_failures', ParamType::Int, 10, min: 3, max: 1000),
			],
			responses: [ResponseType::Ban, ResponseType::NotifyAdmin],
			defaultResponses: [ResponseType::Ban],
			cost: CostClass::OnFailureOnly,
			stores: [],
			texts: static fn (IL10N $l): CheckTexts => new CheckTexts('Test', 'Test', 'Test', 'Fires at {min_failures}.', 'Test', 'Test'),
			internal: $internal,
		);
	}

	public function testUpdateCheckValidatesEverythingBeforeSaving(): void {
		$this->settings->expects($this->never())->method('setMode');
		$this->settings->expects($this->never())->method('setParam');
		$this->settings->expects($this->never())->method('updateCheck');
		$this->audit->expects($this->never())->method('log');

		$response = $this->answer(fn () => $this->checkApi->updateCheck(self::CHECK, 'observe', ['ban'], ['window' => 600, 'min_failures' => 2]));

		$this->assertSame(Http::STATUS_BAD_REQUEST, $response->getStatus());
		$this->assertSame(['message' => '"min_failures" must be at least 3.', 'param' => 'min_failures', 'reason' => 'too_small'], $response->getData());
	}

	public function testUpdateCheckSavesAndAudits(): void {
		// Text as typed into a field is parsed like occ does it.
		$this->settings->expects($this->once())->method('updateCheck')
			->with(self::CHECK, Mode::Observe, ['window' => 600, 'min_failures' => 20], [ResponseType::Ban, ResponseType::NotifyAdmin])
			->willReturn(['mode' => 'observe', 'params' => ['min_failures' => 20]]);
		$this->audit->expects($this->once())->method('log')->with('check %s changed by %s: %s', $this->callback(
			fn (array $p): bool => $p['check'] === self::CHECK && $p['actor'] === 'alice' && str_contains((string)$p['change'], '"min_failures":20') && !str_contains((string)$p['change'], 'window'),
		));

		$response = $this->answer(fn () => $this->checkApi->updateCheck(self::CHECK, 'observe', ['ban', 'notify_admin'], ['window' => '10m', 'min_failures' => 20]));
		$this->assertSame(Http::STATUS_OK, $response->getStatus());
	}

	public function testAChangeThatChangesNothingIsNotAudited(): void {
		$this->settings->method('updateCheck')->willReturn([]);
		$this->audit->expects($this->never())->method('log');
		$this->assertSame(Http::STATUS_OK, $this->answer(fn () => $this->checkApi->updateCheck(self::CHECK, 'protect'))->getStatus());
	}

	public function testUpdateCheckRefusesUnknownResponsesAndModes(): void {
		$this->settings->expects($this->never())->method('setResponses');
		$this->assertSame('unknown_response', $this->answer(fn () => $this->checkApi->updateCheck(self::CHECK, null, ['kill_session']))->getData()['reason']);
		$this->assertSame('unknown_response', $this->answer(fn () => $this->checkApi->updateCheck(self::CHECK, null, [['nested']]))->getData()['reason']);
		$this->assertSame('unknown_mode', $this->answer(fn () => $this->checkApi->updateCheck(self::CHECK, 'everything'))->getData()['reason']);
		$this->assertSame('unknown_param', $this->answer(fn () => $this->checkApi->updateCheck(self::CHECK, null, null, ['nope' => 1]))->getData()['reason']);
	}

	public function testUpdateCheckExplainsAMissingRequirement(): void {
		$this->settings->method('updateCheck')->willThrowException(new InvalidParamException('mode_unavailable', ['why' => 'memory_cache']));
		$response = $this->answer(fn () => $this->checkApi->updateCheck(self::CHECK, 'protect'));
		$this->assertSame(Http::STATUS_BAD_REQUEST, $response->getStatus());
		$this->assertStringContainsString('Needs a memory cache', $response->getData()['message']);
	}

	public function testInternalAndUnknownChecksAreNotConfigurable(): void {
		foreach (['internal_one', 'no_such_check'] as $id) {
			try {
				$this->checkApi->updateCheck($id, 'off');
				$this->fail('Expected a 404 for ' . $id);
			} catch (OCSNotFoundException) {
				$this->addToAssertionCount(1);
			}
		}
		$this->expectException(OCSNotFoundException::class);
		$this->checkApi->resetCheck('internal_one');
	}

	public function testResetCheckIsAudited(): void {
		$this->settings->expects($this->once())->method('resetCheck')->with(self::CHECK);
		$this->audit->expects($this->once())->method('log')->with('check %s reset to defaults by %s', ['check' => self::CHECK, 'actor' => 'alice']);
		$this->assertSame(Http::STATUS_OK, $this->answer(fn () => $this->checkApi->resetCheck(self::CHECK))->getStatus());
	}

	public function testDetectionFiltersAreValidatedAndPassedOn(): void {
		$this->assertSame('severity', $this->answer(fn () => $this->detectionApi->detections(severity: 'huge'))->getData()['param']);
		$this->assertSame('address', $this->answer(fn () => $this->detectionApi->detections(address: 'not-an-ip'))->getData()['param']);
		$this->assertSame('mode', $this->answer(fn () => $this->detectionApi->detections(mode: 'maybe'))->getData()['param']);
		$this->assertSame('limit', $this->answer(fn () => $this->detectionApi->detections(limit: 101))->getData()['param']);
		$this->assertSame('check', $this->answer(fn () => $this->detectionApi->detections(check: 'Bad Id'))->getData()['param']);
		$this->assertSame('offset', $this->answer(fn () => $this->detectionApi->detections(offset: -1))->getData()['param']);

		$captured = null;
		$this->detectionMapper->method('findList')->willReturnCallback(function (DetectionFilter $filter) use (&$captured): array {
			$captured = $filter;
			return [];
		});
		$this->detectionMapper->expects($this->never())->method('count');
		$this->detections->method('rows')->willReturn([]);

		$response = $this->detectionApi->detections('a_check, other_check', 'high,critical', ' bob ', '2001:DB8::1', 'observed', 1_789_000_000, 10, 20);

		$this->assertSame(['detections' => [], 'hasMore' => false], $response->getData());
		$this->assertInstanceOf(DetectionFilter::class, $captured);
		$this->assertSame(['a_check', 'other_check'], $captured->checkIds);
		$this->assertSame(['high', 'critical'], $captured->severities);
		$this->assertSame('bob', $captured->uid);
		$this->assertSame('2001:db8::1', $captured->ip);
		$this->assertFalse($captured->enforced);
		$this->assertSame(1_789_000_000, $captured->since);
		$this->assertSame(11, $captured->limit, 'one more, to tell whether there are more');
		$this->assertSame(20, $captured->offset);
	}

	public function testAMissingDetectionIsNotFound(): void {
		$this->detectionMapper->method('findById')->willThrowException(new DoesNotExistException(''));
		$this->expectException(OCSNotFoundException::class);
		$this->detectionApi->detection(5);
	}

	public function testAddBanValidatesItsInput(): void {
		$this->banService->expects($this->never())->method('banManually');
		$this->assertSame('level', $this->answer(fn () => $this->banApi->addBan('203.0.113.7', 4))->getData()['param']);
		$this->assertSame('duration', $this->answer(fn () => $this->banApi->addBan('203.0.113.7', 1, 60))->getData()['param']);
		$this->assertSame('duration', $this->answer(fn () => $this->banApi->addBan('203.0.113.7', 1, 91 * 86400))->getData()['param']);
		$this->assertSame('note', $this->answer(fn () => $this->banApi->addBan('203.0.113.7', 1, null, str_repeat('x', 256)))->getData()['param']);
		$this->assertSame('target', $this->answer(fn () => $this->banApi->addBan('example.com'))->getData()['param']);
		$this->assertSame('target', $this->answer(fn () => $this->banApi->addBan('203.0.113.0/abc'))->getData()['param']);
	}

	public function testAddBanNeverBlocksTheAdminsOwnAddressOrNetwork(): void {
		$this->banService->expects($this->never())->method('banManually');
		$this->assertStringContainsString('your own address', $this->answer(fn () => $this->banApi->addBan('192.0.2.10'))->getData()['message']);
		$this->assertStringContainsString('your own address', $this->answer(fn () => $this->banApi->addBan('192.0.2.0/24'))->getData()['message']);
	}

	public function testAddBanRefusesTheServerAndTheAllowlist(): void {
		$this->addresses->method('isNeverBlocked')->willReturnCallback(static fn (SourceKey $s): bool => $s->isLoopback());
		$this->addresses->method('isBypassListed')->willReturnCallback(static fn (SourceKey $s): bool => $s->ip === '198.51.100.1');
		$this->banService->expects($this->never())->method('banManually');
		$this->assertStringContainsString('never blocked', $this->answer(fn () => $this->banApi->addBan('127.0.0.1'))->getData()['message']);
		$this->assertStringContainsString('allowlist', $this->answer(fn () => $this->banApi->addBan('198.51.100.1'))->getData()['message']);
	}

	public function testAddBanRefusesANetworkAroundTheAllowlist(): void {
		$this->banService->method('banManually')->willThrowException(new BanRefusedException('198.51.100.0/24'));
		$response = $this->answer(fn () => $this->banApi->addBan('198.51.100.0/24'));
		$this->assertSame('target', $response->getData()['param']);
		$this->assertStringContainsString('198.51.100.0/24 contains this server, a loopback address or an address on the brute-force allowlist', $response->getData()['message']);
	}

	public function testAddBanBlocksAndAudits(): void {
		$ban = new Ban();
		$ban->setReference('K7Q2MPXA');
		$ban->setCidr('203.0.113.7/32');
		$this->banService->expects($this->once())->method('banManually')->with('203.0.113.7', 2, 'alice', 'scanner', 7200)->willReturn($ban);
		$this->audit->expects($this->once())->method('log')->with('block %s (%s) added by %s: %s', ['reference' => 'K7Q2-MPXA', 'cidr' => '203.0.113.7/32', 'actor' => 'alice', 'note' => 'scanner']);
		$this->assertSame(Http::STATUS_OK, $this->answer(fn () => $this->banApi->addBan(' 203.0.113.7 ', 2, 7200, ' scanner '))->getStatus());
	}

	public function testLiftBanNeedsANote(): void {
		$this->banService->expects($this->never())->method('lift');
		$this->assertSame('note', $this->answer(fn () => $this->banApi->liftBan(1, '  '))->getData()['param']);
		$this->assertSame('note', $this->answer(fn () => $this->banApi->liftBan(1, str_repeat('x', 256)))->getData()['param']);
	}

	public function testLiftBanLiftsOnceAndAudits(): void {
		$ban = new Ban();
		$ban->setReference('K7Q2MPXA');
		$ban->setCidr('203.0.113.7/32');
		$this->banMapper->method('findById')->with(3)->willReturn($ban);
		$this->banService->expects($this->once())->method('lift')->with($ban, 'alice', 'false positive');
		$this->audit->expects($this->once())->method('log')->with('block %s (%s) lifted by %s: %s', $this->anything());
		$this->assertSame(Http::STATUS_OK, $this->answer(fn () => $this->banApi->liftBan(3, 'false positive'))->getStatus());
	}

	public function testLiftingALiftedBanChangesNothing(): void {
		$ban = new Ban();
		$ban->setLiftedAt(1_789_000_000);
		$this->banMapper->method('findById')->willReturn($ban);
		$this->banService->expects($this->never())->method('lift');
		$this->audit->expects($this->never())->method('log');
		$this->assertSame(Http::STATUS_OK, $this->answer(fn () => $this->banApi->liftBan(3, 'again'))->getStatus());
	}

	public function testLiftingAMissingBanIsNotFound(): void {
		$this->banMapper->method('findById')->willThrowException(new DoesNotExistException(''));
		$this->expectException(OCSNotFoundException::class);
		$this->banApi->liftBan(3, 'note');
	}

	public function testLearningModeActions(): void {
		$this->learning->expects($this->once())->method('start')->with(14, 'alice');
		$this->learning->expects($this->once())->method('extend')->with(7, 'alice');
		$this->learning->expects($this->once())->method('stop')->with('alice');
		$this->assertSame(Http::STATUS_OK, $this->answer(fn () => $this->settingsApi->updateLearning('start', 14))->getStatus());
		$this->assertSame(Http::STATUS_OK, $this->answer(fn () => $this->settingsApi->updateLearning('extend', 7))->getStatus());
		$this->assertSame(Http::STATUS_OK, $this->answer(fn () => $this->settingsApi->updateLearning('stop'))->getStatus());
		$this->assertSame('days', $this->answer(fn () => $this->settingsApi->updateLearning('start', 31))->getData()['param']);
		$this->assertSame('days', $this->answer(fn () => $this->settingsApi->updateLearning('extend', 0))->getData()['param']);
		$this->assertSame('action', $this->answer(fn () => $this->settingsApi->updateLearning('forever'))->getData()['param']);
	}

	public function testSettingsRefuseInternalAndUnknownKeys(): void {
		$this->settings->expects($this->never())->method('updateGlobals');
		foreach (['attempts_flood_until', 'installed_at', GlobalSettings::LEARNING_UNTIL, 'no_such_setting'] as $name) {
			$response = $this->answer(fn () => $this->settingsApi->updateSettings([$name => 1]));
			$this->assertSame(Http::STATUS_BAD_REQUEST, $response->getStatus(), $name);
			$this->assertSame($name, $response->getData()['param']);
		}
	}

	public function testSettingsValidateEverythingBeforeSaving(): void {
		$this->settings->expects($this->never())->method('updateGlobals');
		$response = $this->answer(fn () => $this->settingsApi->updateSettings([GlobalSettings::BAN_DURATION_1 => '2h', GlobalSettings::BAN_NET_AFTER => 1]));
		$this->assertSame(Http::STATUS_BAD_REQUEST, $response->getStatus());
		$this->assertSame(GlobalSettings::BAN_NET_AFTER, $response->getData()['param']);
	}

	public function testSettingsAreSavedAndTheMasterSwitchIsAuditedOnItsOwn(): void {
		$saved = [];
		$this->settings->method('updateGlobals')->willReturnCallback(function (array $values) use (&$saved): array {
			$saved = $values;
			return $values;
		});
		$logged = [];
		$this->audit->method('log')->willReturnCallback(function (string $message, array $params) use (&$logged): void {
			$logged[] = [$message, $params];
		});

		$this->settingsApi->updateSettings([GlobalSettings::ENABLED => false, GlobalSettings::BAN_DURATION_1 => '2h']);

		$this->assertSame([GlobalSettings::ENABLED => false, GlobalSettings::BAN_DURATION_1 => 7200], $saved);
		$this->assertSame(['intrusion detection turned %s by %s', ['state' => 'off', 'actor' => 'alice']], $logged[0]);
		$this->assertSame('settings changed by %s: %s', $logged[1][0]);
	}

	public function testResetAllIsAudited(): void {
		$this->transfer->expects($this->once())->method('resetAll');
		$this->audit->expects($this->once())->method('log')->with('all settings reset to defaults by %s', ['actor' => 'alice']);
		$this->settingsApi->resetSettings();
	}

	public function testTheProtectionLevelIsAppliedAndAudited(): void {
		$changes = ['checks' => [self::CHECK => ['min_failures' => 5]], 'settings' => []];
		$this->levels->expects($this->once())->method('apply')->with(ProtectionLevel::Strict)->willReturn($changes);
		$this->settings->method('protectionLevel')->willReturn(ProtectionLevel::Strict);
		$this->checks->method('all')->willReturn(['checks' => [], 'categories' => []]);
		$this->audit->expects($this->once())->method('log')->with('protection level set to %s by %s: %s', ['level' => 'strict', 'actor' => 'alice', 'change' => json_encode($changes)]);
		$response = $this->checkApi->updateProtectionLevel('strict');
		$this->assertSame(Http::STATUS_OK, $response->getStatus());
		$this->assertSame('strict', $response->getData()['level']);
	}

	public function testCustomAndUnknownLevelsAreRefusedBeforeAnythingChanges(): void {
		$this->levels->expects($this->never())->method('apply');
		$this->audit->expects($this->never())->method('log');
		$this->assertSame(Http::STATUS_BAD_REQUEST, $this->answer(fn () => $this->checkApi->updateProtectionLevel('custom'))->getStatus());
		$this->assertSame(Http::STATUS_BAD_REQUEST, $this->answer(fn () => $this->checkApi->updateProtectionLevel('paranoid'))->getStatus());
	}
}
