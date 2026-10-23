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
use OCA\IntrusionDetection\AdminChange\ApprovalService;
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
		$this->levels = $this->createMock(ProtectionLevels::class);

		$actors = new ActorResolver($session);
		$request = $this->createMock(IRequest::class);
		$this->checkApi = new CheckApiController($request, $l, $actors, $this->registry, $this->settings, $this->status, $this->checks, $this->levels, $this->createMock(ApprovalService::class));
		$this->detectionApi = new DetectionApiController($request, $l, $actors, $this->detectionMapper, $this->detections, $this->createMock(DailyStats::class), $this->createMock(LookupService::class));
		$this->banApi = new BanApiController($request, $l, $actors, $time, $this->banMapper, $this->banService, $this->bans);
		$this->settingsApi = new SettingsApiController($request, $l, $actors, $this->status, $this->learning, $this->globalSettings, $this->transfer);
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

	public function testAChangeOfACheckGoesToTheEditorAsGivenWithTheActor(): void {
		$this->settings->expects($this->once())->method('changeCheck')
			->with(self::CHECK, 'observe', ['ban'], ['window' => '10m'], 'alice')
			->willReturn(['mode' => 'observe']);
		$this->assertSame(['id' => self::CHECK], $this->checkApi->updateCheck(self::CHECK, 'observe', ['ban'], ['window' => '10m'])->getData());
	}

	public function testAResetGoesToTheEditorWithTheActor(): void {
		$this->settings->expects($this->once())->method('resetCheck')->with(self::CHECK, 'alice');
		$this->assertSame(Http::STATUS_OK, $this->checkApi->resetCheck(self::CHECK)->getStatus());
	}

	public function testTheProtectionLevelIsAppliedWithTheActorAndAnswersWithTheChecks(): void {
		$this->levels->expects($this->once())->method('apply')->with(ProtectionLevel::Strict, 'alice');
		$this->settings->method('protectionLevel')->willReturn(ProtectionLevel::Strict);
		$this->checks->method('all')->willReturn(['checks' => [], 'categories' => []]);
		$this->assertSame(['level' => 'strict', 'checks' => ['checks' => [], 'categories' => []]], $this->checkApi->updateProtectionLevel('strict')->getData());
	}

	public function testABlockByHandGoesToTheServiceAsGivenWithTheActor(): void {
		$ban = new Ban();
		$this->banService->expects($this->once())->method('banManually')->with(' 203.0.113.7 ', 2, 'alice', ' scanner ', 7200)->willReturn($ban);
		$this->assertSame(['id' => 1], $this->banApi->addBan(' 203.0.113.7 ', 2, 7200, ' scanner ')->getData());
	}

	public function testALiftGoesToTheServiceWithTheActor(): void {
		$this->banService->expects($this->once())->method('liftById')->with(3, 'alice', 'false positive')->willReturn(new Ban());
		$this->assertSame(Http::STATUS_OK, $this->banApi->liftBan('3', 'false positive')->getStatus());
	}

	public function testLiftingAMissingBanIsNotFound(): void {
		$this->banService->method('liftById')->willThrowException(new DoesNotExistException(''));
		$this->expectException(OCSNotFoundException::class);
		$this->banApi->liftBan('3', 'note');
	}

	public function testSettingsGoToTheTransferAsGivenWithTheActor(): void {
		$this->transfer->expects($this->once())->method('changeSettings')->with([GlobalSettings::BAN_DURATION_1 => '2h'], 'alice');
		$this->assertSame(['settings' => [], 'templates' => []], $this->settingsApi->updateSettings([GlobalSettings::BAN_DURATION_1 => '2h'])->getData());
	}

	public function testAResetOfAllSettingsHasTheActor(): void {
		$this->transfer->expects($this->once())->method('resetAll')->with('alice');
		$this->settingsApi->resetSettings();
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
		$this->detectionApi->detection('5');
	}

	public function testLiftBanNeedsANote(): void {
		$this->banService->expects($this->never())->method('liftById');
		$this->assertSame(['param' => 'note', 'reason' => 'required'], array_diff_key($this->banApi->liftBan('1', '  ')->getData(), ['message' => '']));
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

	public function testCustomAndUnknownLevelsAreRefusedBeforeAnythingChanges(): void {
		$this->levels->expects($this->never())->method('apply');
		$this->assertSame(Http::STATUS_BAD_REQUEST, $this->answer(fn () => $this->checkApi->updateProtectionLevel('custom'))->getStatus());
		$this->assertSame(Http::STATUS_BAD_REQUEST, $this->answer(fn () => $this->checkApi->updateProtectionLevel('paranoid'))->getStatus());
	}
}
