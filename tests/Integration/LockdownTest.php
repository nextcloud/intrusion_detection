<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Admin\LockdownOverview;
use OCA\IntrusionDetection\Admin\StatusService;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\BackgroundJob\LockdownJob;
use OCA\IntrusionDetection\Check\Checks\ResetProbing;
use OCA\IntrusionDetection\Check\Checks\ResetProbingDetector;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Command\Lockdown as LockdownCommand;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Keys;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCA\IntrusionDetection\Controller\LockdownApiController;
use OCA\IntrusionDetection\Db\Lockdown;
use OCA\IntrusionDetection\Db\LockdownMapper;
use OCA\IntrusionDetection\Detection\AttemptRecorder;
use OCA\IntrusionDetection\Incident\IncidentQuery;
use OCA\IntrusionDetection\Incident\Sources\LockdownSource;
use OCA\IntrusionDetection\Listener\ConfirmDialogListener;
use OCA\IntrusionDetection\Listener\LoginNoticeListener;
use OCA\IntrusionDetection\Listener\ResetRequestedListener;
use OCA\IntrusionDetection\Lockdown\LockdownEffect;
use OCA\IntrusionDetection\Lockdown\LockdownException;
use OCA\IntrusionDetection\Lockdown\LockdownService;
use OCA\IntrusionDetection\Lockdown\LockdownState;
use OCA\IntrusionDetection\Notification\LockdownNotices;
use OCA\IntrusionDetection\Notification\Notifier;
use OCA\IntrusionDetection\OpenMetrics\LockdownActiveMetric;
use OCA\IntrusionDetection\Response\ResetMailSuppressor;
use OCA\IntrusionDetection\Risk\RiskLimits;
use OCA\IntrusionDetection\Risk\RiskScorer;
use OCA\IntrusionDetection\Sensitive\SensitiveSession;
use OCP\AppFramework\Http;
use OCP\AppFramework\Http\Events\BeforeLoginTemplateRenderedEvent;
use OCP\AppFramework\Http\Events\BeforeTemplateRenderedEvent;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\AppFramework\Services\IInitialState;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IUser;
use OCP\IUserManager;
use OCP\L10N\IFactory;
use OCP\OpenMetrics\Metric;
use OCP\Security\Events\PasswordResetRequestedEvent;
use OCP\Server;
use OCP\Util;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * Lockdown mode (concept section 11.14): starting, extending and ending
 * it, each effect with its switch, the notices, the audit log, occ, the
 * admin API, the metric and the incident timeline.
 */
#[Group('DB')]
class LockdownTest extends SensitiveTestCase {
	private LockdownService $lockdown;
	private LockdownState $lockdownState;

	protected function setUp(): void {
		parent::setUp();
		$this->lockdown = Server::get(LockdownService::class);
		$this->lockdownState = Server::get(LockdownState::class);
	}

	public function testALockdownStartsRunsAndIsRecorded(): void {
		$this->assertFalse($this->lockdownState->isActive());
		$started = $this->lockdown->start(6 * 3600, "credential stuffing\nfrom botnet", 'admin');
		$this->assertTrue($this->lockdownState->isActive());
		$this->assertEqualsWithDelta(time() + 6 * 3600, $this->lockdownState->until(), 2);
		$info = $this->lockdownState->info();
		$this->assertSame('admin', $info['startedBy']);
		$this->assertSame('credential stuffing from botnet', $info['reason'], 'Control characters are removed');
		$this->assertSame(LockdownEffect::values(), $info['effects'], 'Every effect is on by default');
		$this->assertSame($started->getId(), $info['id']);
		$this->assertSame(implode(',', LockdownEffect::values()), $started->getEffects());
		$this->assertContains('Intrusion detection: lockdown started by admin until ' . gmdate('c', $started->getPlannedEnd()) . ' (credential stuffing from botnet), effects: ' . implode(',', LockdownEffect::values()), $this->audited);

		$this->expectException(LockdownException::class);
		$this->lockdown->start(3600, '', 'admin');
	}

	/**
	 * @return array<string, array{int}>
	 */
	public static function invalidDurations(): array {
		return ['59 minutes' => [3540], '25 hours' => [25 * 3600], 'nothing' => [0]];
	}

	#[DataProvider('invalidDurations')]
	public function testALockdownLastsOneToTwentyFourHours(int $duration): void {
		$this->expectException(\InvalidArgumentException::class);
		$this->lockdown->start($duration, '', 'admin');
	}

	public function testItCanBeExtendedButNeverBeyondTwentyFourHoursFromNow(): void {
		try {
			$this->lockdown->extend(3600, 'admin');
			$this->fail('Nothing to extend');
		} catch (LockdownException) {
		}
		$this->lockdown->start(6 * 3600, '', 'admin');
		$until = $this->lockdown->extend(2 * 3600, 'admin');
		$this->assertEqualsWithDelta(time() + 8 * 3600, $until, 2);
		$this->assertSame($until, Server::get(LockdownMapper::class)->findById($this->lockdownState->info()['id'])?->getPlannedEnd());
		$until = $this->lockdown->extend(20 * 3600, 'admin');
		$this->assertEqualsWithDelta(time() + 24 * 3600, $until, 2, 'Capped');
		$this->assertContains('Intrusion detection: lockdown extended by admin until ' . gmdate('c', $until), $this->audited);
	}

	public function testItCanBeEndedEarlyAndEveryAdministratorIsTold(): void {
		$started = $this->lockdown->start(6 * 3600, 'botnet', 'admin');
		$startNotices = $this->notificationsFor('admin', LockdownNotices::SUBJECT_STARTED);
		$this->assertCount(1, $startNotices);
		$prepared = Server::get(Notifier::class)->prepare($startNotices[0], 'en');
		$this->assertStringStartsWith('Lockdown until ', $prepared->getParsedSubject());
		$this->assertStringContainsString('It was started by admin.', $prepared->getParsedMessage());
		$this->assertStringContainsString('Reason: "botnet"', $prepared->getParsedMessage());

		$this->assertTrue($this->lockdown->end('admin'));
		$this->assertFalse($this->lockdownState->isActive());
		$this->assertSame(0, $this->settings->getInt(GlobalSettings::LOCKDOWN_UNTIL));
		$this->assertFalse($this->lockdown->end('admin'), 'Nothing left to end');
		$entry = Server::get(LockdownMapper::class)->findById((int)$started->getId());
		$this->assertSame('admin', $entry?->getEndedBy());
		$this->assertEqualsWithDelta(time(), $entry?->getEndedAt(), 2);

		$ended = $this->notificationsFor('admin', LockdownNotices::SUBJECT_ENDED);
		$this->assertCount(1, $ended);
		$this->assertSame('The lockdown has ended', Server::get(Notifier::class)->prepare($ended[0], 'en')->getParsedSubject());
		$withdrawn = array_filter(CapturingNotificationApp::$processed, static fn ($n): bool => $n->getObjectType() === LockdownNotices::OBJECT_TYPE && $n->getObjectId() === (string)$started->getId() && $n->getSubject() === LockdownNotices::SUBJECT_STARTED);
		$this->assertNotSame([], $withdrawn, 'The notice of the start is withdrawn');
		$this->assertContains('Intrusion detection: lockdown ended by admin', $this->audited);
	}

	public function testItEndsByItselfAndTheBackgroundJobTellsTheAdministrators(): void {
		$started = $this->lockdown->start(3600, '', 'occ');
		$this->settings->setGlobal(GlobalSettings::LOCKDOWN_UNTIL, time() - 10);
		$this->assertFalse($this->lockdownState->isActive(), 'The effects stop at the planned time, job or not');

		$job = new LockdownJob(Server::get(ITimeFactory::class), $this->lockdown);
		$job->setId('1');
		$job->setLastRun(0);
		$job->start(Server::get(\OCP\BackgroundJob\IJobList::class));
		$this->assertSame(0, $this->settings->getInt(GlobalSettings::LOCKDOWN_UNTIL));
		$entry = Server::get(LockdownMapper::class)->findById((int)$started->getId());
		$this->assertSame(Lockdown::ACTOR_AUTOMATIC, $entry?->getEndedBy());
		$this->assertCount(1, $this->notificationsFor('admin', LockdownNotices::SUBJECT_ENDED));
		$prepared = Server::get(Notifier::class)->prepare($this->notificationsFor('admin', LockdownNotices::SUBJECT_ENDED)[0], 'en');
		$this->assertStringContainsString('It ended at its planned time.', $prepared->getParsedMessage());
		$this->assertStringContainsString('It was started by a command on the server.', $prepared->getParsedMessage());
		$this->assertFalse($this->lockdown->expireIfDue(), 'Once');
	}

	public function testItDoesNothingWhileIntrusionDetectionIsOff(): void {
		$this->lockdown->start(3600, '', 'admin');
		$this->settings->setGlobal(GlobalSettings::ENABLED, false);
		$this->assertFalse($this->lockdownState->isActive());
		$this->assertFalse($this->lockdownState->applies(LockdownEffect::Login));
	}

	public function testEveryPasswordLoginNeedsConfirmation(): void {
		$bob = $this->user('ids-lockdown-bob', null);
		$alice = $this->user('ids-lockdown-alice', 'alice@example.com');
		$this->lockdown->start(3600, '', 'admin');

		$this->startSession($alice);
		$this->login($alice);
		$this->assertSame(StepUpState::PENDING, $this->stepUp()?->status, 'A code is sent');
		$this->assertSame(['lockdown'], $this->stepUp()?->policies);

		$this->session->clear();
		$this->startSession($bob);
		$this->login($bob);
		$this->assertSame(StepUpState::REFUSED, $this->stepUp()?->status, 'Nothing can confirm: refused by default');
	}

	public function testARememberedDeviceCountsOnlyWhenAllowed(): void {
		$alice = $this->user('ids-lockdown-alice', 'alice@example.com');
		$this->knownDevices()->remember($alice, null, 'Firefox');
		$this->nextRequest();
		$this->lockdown->start(3600, '', 'admin');

		$this->startSession($alice);
		$this->login($alice);
		$this->assertSame(StepUpState::PENDING, $this->stepUp()?->status, 'Not by default');

		$this->settings->setGlobal(GlobalSettings::LOCKDOWN_KNOWN_DEVICE_OK, true);
		$this->session->clear();
		$this->nextRequest();
		$this->startSession($alice);
		$this->login($alice);
		$this->assertNull($this->stepUp());
		$this->assertSame('known_device', $this->state->get('confirmation')['by'] ?? null);
	}

	public function testWithoutTheLoginEffectLoginsGoAhead(): void {
		$bob = $this->user('ids-lockdown-bob', null);
		$this->lockdown->start(3600, '', 'admin', array_values(array_diff(LockdownEffect::values(), ['login'])));
		$this->startSession($bob);
		$this->login($bob);
		$this->assertNull($this->stepUp());
	}

	public function testEverySessionMustConfirmSensitiveActions(): void {
		$alice = $this->user('ids-lockdown-alice', 'alice@example.com');
		$this->startSession($alice);
		$this->assertNull($this->sensitiveSession()->riskReason($this->state, $alice->getUID()));
		$this->lockdown->start(3600, '', 'admin');
		$this->assertSame(SensitiveSession::REASON_LOCKDOWN, $this->sensitiveSession()->riskReason($this->state, $alice->getUID()));
		$this->lockdown->end('admin');
		$this->lockdown->start(3600, '', 'admin', ['login']);
		$this->assertNull($this->sensitiveSession()->riskReason($this->state, $alice->getUID()), 'Switched off');
	}

	public function testNewDevicesAreRefusedOnlyWithThatEffect(): void {
		$alice = $this->user('ids-lockdown-alice', 'alice@example.com');
		$this->startSession($alice);
		$this->route = 'settings.authsettings.create';
		$this->lockdown->start(3600, '', 'admin', ['login']);
		$this->sensitiveSession()->confirmed($this->state, $alice->getUID(), 'email_code');
		$this->assertNull($this->actions()->check($this->state, $this->route, $alice->getUID(), '/'));
		$this->lockdown->end('admin');
		$this->lockdown->start(3600, '', 'admin', ['devices']);
		$this->assertSame('devices_locked', $this->actions()->check($this->state, $this->route, $alice->getUID(), '/')?->error);
		$this->assertContains('Intrusion detection: new device of ' . $alice->getUID() . ' refused: lockdown', $this->audited);
	}

	public function testPasswordResetIsPausedForEveryoneWithTheUsualAnswer(): void {
		$this->appConfig->setValueString(Application::APP_ID, Keys::mode(ResetProbing::ID), Mode::Off->value);
		$this->assertFalse($this->reset()->isEmailPrevented());
		$this->lockdown->start(3600, '', 'admin');
		$this->assertTrue($this->reset()->isEmailPrevented(), 'Even with the reset check off');
		$this->lockdown->end('admin');
		$this->lockdown->start(3600, '', 'admin', ['login']);
		$this->assertFalse($this->reset()->isEmailPrevented(), 'Switched off');
	}

	public function testTheLimitsAreLoweredInOnePlaceWithTheRiskScore(): void {
		$scorer = Server::get(RiskScorer::class);
		$this->assertSame(10, $this->limitFor($scorer, 10, 9), 'No lockdown');
		$this->lockdown->start(3600, '', 'admin');
		$this->assertSame(5, $this->limitFor($scorer, 10, 5), 'Halved');
		$this->assertSame(2, $this->limitFor($scorer, 3, 2), 'Never below 2');
		$this->assertSame(2, $this->limitFor($scorer, 2, 2), 'A limit of 2 stays');
		$this->settings->setGlobal(GlobalSettings::LOCKDOWN_FACTOR, 0.25);
		$this->assertSame(3, $this->limitFor($scorer, 10, 3), 'The factor is a setting');
		$limits = $scorer->limits(null, ['min_failures' => [10, 3]]);
		$this->assertEquals(['lockdownLimits' => ['factor' => 0.25, 'caps' => []], 'loweredLimits' => ['min_failures' => ['plain' => 10, 'effective' => 3]]], array_intersect_key($limits->facts(), ['lockdownLimits' => 1, 'loweredLimits' => 1]));
		$this->lockdown->end('admin');
		$this->lockdown->start(3600, '', 'admin', ['login']);
		$this->assertSame(10, $this->limitFor($scorer, 10, 9), 'Switched off');
	}

	public function testShareLinkPasswordsHaveTheStricterLimit(): void {
		$scorer = Server::get(RiskScorer::class);
		$share = fn (int $measured): RiskLimits => $scorer->limits(null, ['password_min_per_source' => [5, $measured]], $this->lockdownState->sharePasswordLimit() === null ? [] : ['password_min_per_source' => (int)$this->lockdownState->sharePasswordLimit()]);
		$this->assertFalse($share(3)->reached());
		$this->lockdown->start(3600, '', 'admin', ['share_password']);
		$this->assertTrue($share(3)->reached(), '3 instead of 5');
		$this->assertFalse($share(2)->reached());
		$this->lockdown->end('admin');
		$this->lockdown->start(3600, '', 'admin');
		$this->assertSame(3, $share(3)->of('password_min_per_source'), 'Halving 5 gives 3 as well; the two never compound below it');
	}

	public function testOccStartsExtendsShowsAndEndsIt(): void {
		$tester = new CommandTester(Server::get(LockdownCommand::class));
		$this->assertSame(0, $tester->execute([]));
		$this->assertStringContainsString('No lockdown is running.', $tester->getDisplay());

		$this->assertSame(0, $tester->execute(['--start' => '6h', '--reason' => 'botnet', '--effects' => 'login,devices']));
		$this->assertTrue($this->lockdownState->isActive());
		$this->assertSame('occ', $this->lockdownState->info()['startedBy']);
		$this->assertSame(['login', 'devices'], $this->lockdownState->info()['effects']);

		$this->assertSame(0, $tester->execute(['--extend' => '2h']));
		$this->assertEqualsWithDelta(time() + 8 * 3600, $this->lockdownState->until(), 2);

		$this->assertSame(0, $tester->execute(['--status' => true]));
		$this->assertStringContainsString('started by occ', $tester->getDisplay());
		$this->assertStringContainsString('Reason: botnet', $tester->getDisplay());
		$this->assertStringContainsString('Effects: login, devices', $tester->getDisplay());

		$this->assertSame(2, $tester->execute(['--start' => '30m']), 'Too short');
		$this->assertSame(2, $tester->execute(['--extend' => 'soon']));

		$this->assertSame(0, $tester->execute(['--end' => true]));
		$this->assertFalse($this->lockdownState->isActive());
		$this->assertSame(Lockdown::ACTOR_OCC, Server::get(LockdownMapper::class)->latest(1)[0]->getEndedBy());
		$this->assertSame(2, $tester->execute(['--start' => '2h', '--effects' => 'everything']), 'Unknown effect');
	}

	public function testTheAdminApiStartsExtendsAndEndsIt(): void {
		$api = $this->api();
		$this->assertFalse($api->index()->getData()['active']);
		$this->assertSame(Http::STATUS_BAD_REQUEST, $api->start(600)->getStatus());
		$this->assertSame('reason', $api->start(3600, str_repeat('x', 201))->getData()['param']);
		$this->assertSame(Http::STATUS_BAD_REQUEST, $api->extend(3600)->getStatus(), 'Nothing to extend');

		$started = $api->start(4 * 3600, 'botnet', ['login', 'reset'])->getData();
		$this->assertTrue($started['active']);
		$this->assertSame('admin', $started['startedBy']);
		$this->assertSame([true, false, false, true, false, false], array_column($started['effects'], 'enabled'));
		$this->assertCount(1, $started['history']);
		$this->assertSame('running', $api->start(3600)->getData()['reason']);

		$extended = $api->extend(3600)->getData();
		$this->assertEqualsWithDelta(time() + 5 * 3600, $extended['until'], 2);
		$ended = $api->end()->getData();
		$this->assertFalse($ended['active']);
		$this->assertSame('admin', $ended['history'][0]['endedBy']);
	}

	public function testTheAdminPageAndItsLockdownEndpointsAlwaysWork(): void {
		$admin = Server::get(IUserManager::class)->get('admin');
		$this->assertInstanceOf(IUser::class, $admin);
		$this->startSession($admin);
		$this->lockdown->start(3600, '', 'admin');
		$this->assertSame(SensitiveSession::REASON_LOCKDOWN, $this->sensitiveSession()->riskReason($this->state, 'admin'), 'Administrators are subject to it');
		foreach (['ocs.intrusion_detection.lockdownapi.end', 'ocs.intrusion_detection.lockdownapi.extend', 'ocs.intrusion_detection.lockdownapi.index', 'ocs.intrusion_detection.adminapi.status', 'settings.adminsettings.index'] as $route) {
			$this->assertNull($this->actions()->check($this->state, $route, 'admin', '/'), $route . ' works during a lockdown without any confirmation');
		}
		$this->assertSame('confirmation_required', $this->actions()->check($this->state, 'ocs.intrusion_detection.adminapi.updatesettings', 'admin', '/')?->error, 'Weakening the protection needs one');
	}

	public function testTheStatusAndTheMetricShowIt(): void {
		$l = Server::get(IFactory::class)->get(Application::APP_ID, 'en');
		$metric = static fn (): array => iterator_to_array(Server::get(LockdownActiveMetric::class)->metrics());
		$this->assertArrayNotHasKey('lockdown', Server::get(StatusService::class)->status($l)['extensions']);
		$this->assertEquals([new Metric(false)], $metric());
		$this->lockdown->start(3600, 'botnet', 'admin');
		$status = Server::get(StatusService::class)->status($l)['extensions']['lockdown'] ?? null;
		$this->assertEquals(['active' => true, 'reason' => 'botnet', 'startedBy' => 'admin'], array_intersect_key((array)$status, ['active' => 1, 'reason' => 1, 'startedBy' => 1]));
		$this->assertEquals([new Metric(true)], $metric());
		$this->assertSame('intrusion_lockdown_active', Server::get(LockdownActiveMetric::class)->name());
	}

	public function testTheIncidentTimelineShowsTheLockdownsOfThePeriod(): void {
		$earlier = $this->lockdown->start(3600, 'first', 'admin');
		$this->lockdown->end('admin');
		$this->lockdown->start(2 * 3600, '', Lockdown::ACTOR_AUTOMATIC);
		$l = Server::get(IFactory::class)->get(Application::APP_ID, 'en');
		$source = new LockdownSource(Server::get(LockdownMapper::class), Server::get(\OCA\IntrusionDetection\Explain\DateFormatter::class));
		$entries = iterator_to_array($source->entriesFor(IncidentQuery::forUser('alice', time() - 3600, time() + 60, time()), $l), false);
		$this->assertCount(2, $entries);
		$this->assertSame('lockdown:' . $earlier->getId(), $entries[0]->id);
		$this->assertSame(LockdownSource::KIND, $entries[0]->kind);
		$this->assertContains('Reason: "first"', $entries[0]->details);
		$this->assertStringContainsString('Started automatically', implode(' ', $entries[1]->details));
		$this->assertSame([], iterator_to_array($source->entriesFor(IncidentQuery::forUser('alice', time() - 86400 * 3, time() - 86400 * 2, time()), $l), false), 'Not from other periods');
		$this->assertSame(['lockdown' => 'Lockdowns'], $source->kinds($l));
	}

	public function testTheLoginPageGetsTheNoticeDuringLockdownOnly(): void {
		$states = [];
		$initialState = $this->createMock(IInitialState::class);
		$initialState->method('provideInitialState')->willReturnCallback(static function (string $key, mixed $value) use (&$states): void {
			$states[$key] = $value;
		});
		$listener = new LoginNoticeListener($this->lockdownState, $this->settings, $initialState, Server::get(IFactory::class)->get(Application::APP_ID, 'en'), Server::get(LoggerInterface::class));
		$event = new BeforeLoginTemplateRenderedEvent(new TemplateResponse('core', 'login'));

		$this->scripts();
		$listener->handle($event);
		$this->assertSame([], $states);
		$this->assertNotContains(LoginNoticeListener::SCRIPT, $this->scripts());

		$this->lockdown->start(3600, '', 'admin');
		$listener->handle($event);
		$this->assertSame(['login-notice' => 'Extra security checks are active. You may be asked to confirm your login.'], $states);
		$this->assertContains(LoginNoticeListener::SCRIPT, $this->scripts());

		$this->settings->setGlobal(GlobalSettings::LOCKDOWN_LOGIN_NOTICE, 'We are under attack. Use your second factor.');
		$listener->handle($event);
		$this->assertSame('We are under attack. Use your second factor.', $states['login-notice']);
	}

	public function testTheConfirmDialogIsLoadedForLoggedInPagesOnly(): void {
		$listener = new ConfirmDialogListener();
		$this->scripts();
		$listener->handle(new BeforeTemplateRenderedEvent(false, new TemplateResponse('core', 'login')));
		$this->assertNotContains(ConfirmDialogListener::SCRIPT, $this->scripts());
		$listener->handle(new BeforeTemplateRenderedEvent(true, new TemplateResponse('files', 'index')));
		$this->assertContains(ConfirmDialogListener::SCRIPT, $this->scripts());
	}

	public function testTheOverviewSaysWhoCannotLogInDuringLockdown(): void {
		$overview = Server::get(LockdownOverview::class)->get(Server::get(IFactory::class)->get(Application::APP_ID, 'en'));
		$this->assertSame(LockdownEffect::values(), array_column($overview['effects'], 'id'));
		$this->assertSame(21600, $overview['defaultDuration']);
		$this->assertSame([3600, 86400, 200], [$overview['minDuration'], $overview['maxDuration'], $overview['maxReason']]);
		$this->assertIsInt($overview['usersWithoutMethod']);
		$this->assertStringContainsString('{lockdown_factor}', $overview['effects'][4]['description'], 'Filled in on the page');
	}

	private function limitFor(RiskScorer $scorer, int $plain, int $measured): int {
		return $scorer->limits(null, ['min_failures' => [$plain, $measured]])->of('min_failures');
	}

	private function reset(): PasswordResetRequestedEvent {
		$event = new PasswordResetRequestedEvent('nobody-' . bin2hex(random_bytes(3)));
		(new ResetRequestedListener(
			$this->settings,
			$this->addresses(),
			Server::get(AttemptRecorder::class),
			Server::get(ResetProbingDetector::class),
			Server::get(ResetMailSuppressor::class),
			Server::get(IUserManager::class),
			$this->request,
			Server::get(LoggerInterface::class),
			$this->lockdownState,
		))->handle($event);
		return $event;
	}

	private function api(): LockdownApiController {
		$this->sessionUser = Server::get(IUserManager::class)->get('admin');
		$this->assertInstanceOf(IUser::class, $this->sessionUser);
		return new LockdownApiController($this->request, Server::get(IFactory::class)->get(Application::APP_ID, 'en'), $this->userSession, $this->lockdown, Server::get(LockdownOverview::class));
	}

	/**
	 * @return list<string> the scripts of this app added to the page since the last call
	 */
	private function scripts(): array {
		$property = new \ReflectionProperty(Util::class, 'scripts');
		$scripts = $property->getValue()[Application::APP_ID] ?? [];
		$property->setValue(null, array_diff_key($property->getValue(), [Application::APP_ID => true]));
		$names = [];
		foreach ($scripts as $script) {
			if (str_starts_with($script, Application::APP_ID . '/js/')) {
				$names[] = substr($script, strlen(Application::APP_ID . '/js/'));
			}
		}
		return $names;
	}
}
