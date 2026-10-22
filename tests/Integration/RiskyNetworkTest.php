<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\Memcache\ArrayCache;
use OCA\IntrusionDetection\Address\AddressCache;
use OCA\IntrusionDetection\Address\Verdict;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Blocklist\SourceRepository;
use OCA\IntrusionDetection\Cache\Caches;
use OCA\IntrusionDetection\Check\Checks\RiskyNetwork\RiskyNetwork;
use OCA\IntrusionDetection\Check\Checks\RiskyNetwork\RiskyNetworkDetector;
use OCA\IntrusionDetection\Check\Checks\StepUpRefused\StepUpRefused;
use OCA\IntrusionDetection\Check\Checks\StepUpUnconfirmed\StepUpUnconfirmed;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Confirm\IConfirmationMethod;
use OCA\IntrusionDetection\Confirm\Reasons\RiskHighReason;
use OCA\IntrusionDetection\Confirm\Reasons\RiskyNetworkReason;
use OCA\IntrusionDetection\Confirm\StepUpPolicy;
use OCA\IntrusionDetection\Confirm\StepUpReasons;
use OCA\IntrusionDetection\Confirm\StepUpState;
use OCA\IntrusionDetection\Db\AttemptMapper;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Guard\RequestContext;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Notification\UserAlerts;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\Risk\AttackTools;
use OCA\IntrusionDetection\Risk\NetworkAttributes;
use OCA\IntrusionDetection\Risk\RiskScorer;
use OCA\IntrusionDetection\Tests\Unit\Cache\FixedCaches;
use OCA\IntrusionDetection\TrustedNetwork\ITrustedNetworks;
use OCA\IntrusionDetection\TrustedNetwork\TrustedNetworks;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IGroupManager;
use OCP\IUser;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;

/**
 * Password logins from hosting and Tor networks (concept section 10.17),
 * and from addresses with a high risk score (section 10.18): the step-up
 * policies `risky_network` and `risk_high`, wired like the app wires them.
 */
#[Group('DB')]
class RiskyNetworkTest extends StepUpTestCase {
	private IUser $alice;
	private RequestContext $context;
	private ?RiskyNetworkDetector $detector = null;

	protected function setUp(): void {
		parent::setUp();
		$this->alice = $this->user('ids-risky', 'alice@example.com');
		$this->context = new RequestContext();
	}

	protected function tearDown(): void {
		Server::get(IGroupManager::class)->get('ids-service-accounts')?->delete();
		parent::tearDown();
	}

	public function testALoginFromAHostingNetworkAsksForConfirmationAndIsRecorded(): void {
		$this->network(['hosting', 'net:aws']);
		$this->login($this->alice);

		$stepUp = $this->stepUp();
		$this->assertSame(StepUpState::PENDING, $stepUp?->status);
		$this->assertSame([StepUpPolicy::RiskyNetwork->value], $stepUp->policies);
		$this->assertSame([IConfirmationMethod::EMAIL_CODE], $stepUp->methods);

		$detections = $this->detectionsOf(RiskyNetwork::ID);
		$this->assertCount(1, $detections);
		$detection = $detections[0];
		$this->assertSame('low', $detection->getSeverity());
		$this->assertTrue($detection->isEnforced());
		$this->assertSame($this->alice->getUID(), $detection->getUid());
		$this->assertSame(['step_up'], array_column($detection->getActionList(), 'type'), 'No notification by default');
		$facts = $detection->getExplanationData()['facts'];
		$this->assertSame(['hosting'], $facts['attributes']);
		$this->assertSame(['Amazon Web Services'], $facts['listNames']);

		$l = Server::get(IFactory::class)->get(Application::APP_ID, 'en');
		$this->assertStringContainsString(
			'logged in with its password from 198.51.100.7, an address of a cloud or hosting provider (Amazon Web Services).',
			implode(' ', Server::get(NarrativeBuilder::class)->build($detection, $l)->happened),
		);
	}

	public function testATorExitNodeCountsToo(): void {
		$this->network(['tor', 'net:tor_exits']);
		$this->login($this->alice);
		$this->assertSame([StepUpPolicy::RiskyNetwork->value], $this->stepUp()?->policies);
		$this->assertSame(['tor'], $this->detectionsOf(RiskyNetwork::ID)[0]->getExplanationData()['facts']['attributes']);
	}

	public function testWithoutANetworkListNothingHappens(): void {
		$this->context->setVerdict(new Verdict());
		$this->login($this->alice);
		$this->assertNull($this->stepUp());
		$this->assertSame([], $this->detectionsOf(RiskyNetwork::ID));
	}

	public function testAnOfficeNetworkIsNeverRisky(): void {
		$this->settingsEditor()->setGlobal(GlobalSettings::RISKY_NETWORK_OFFICE_NETWORKS, ['198.51.100.0/24']);
		$this->network(['hosting']);
		$this->login($this->alice);
		$this->assertNull($this->stepUp());
		$this->assertSame([], $this->detectionsOf(RiskyNetwork::ID));
	}

	public function testMembersOfAnExemptGroupAreNotAsked(): void {
		$group = Server::get(IGroupManager::class)->createGroup('ids-service-accounts');
		$group?->addUser($this->alice);
		$this->settingsEditor()->setGlobal(GlobalSettings::RISKY_NETWORK_EXEMPT_GROUPS, ['ids-service-accounts']);
		$this->network(['hosting']);
		$this->login($this->alice);
		$this->assertNull($this->stepUp());

		$bob = $this->user('ids-risky-bob', 'bob@example.com');
		$this->session->id = null;
		$this->login($bob);
		$this->assertNotNull($this->stepUp(), 'Only members are exempt');
	}

	public function testTrustedNetworksSkipIt(): void {
		Server::get(TrustedNetworks::class)->trust($this->alice->getUID(), SourceKey::fromIp('198.51.100.200'));
		$this->network(['tor']);
		$this->login($this->alice);
		$this->assertNull($this->stepUp());
		$this->assertSame([], $this->detectionsOf(RiskyNetwork::ID));
	}

	public function testAppPasswordsAreNeverAffected(): void {
		$this->network(['hosting']);
		$this->headers['Authorization'] = 'Basic ' . base64_encode('alice:app-password');
		$this->login($this->alice, 'xxxxx-xxxxx-xxxxx-xxxxx-xxxxx', tokenLogin: true);
		$this->assertNull($this->stepUp());
		$this->assertSame([], $this->detectionsOf(RiskyNetwork::ID));
	}

	public function testWithoutAWayToConfirmTheLoginIsAllowedAndBothAreTold(): void {
		$bob = $this->user('ids-risky-noemail', null);
		$this->network(['hosting']);
		$this->login($bob);
		$this->assertNull($this->stepUp(), 'The default for this policy allows the login');
		$detection = $this->detectionsOf(StepUpUnconfirmed::ID)[0];
		$this->assertSame(['notify_admin', 'notify_user'], array_column($detection->getActionList(), 'type'));
	}

	public function testThePolicyCanRefuseInstead(): void {
		$this->settingsEditor()->setGlobal(StepUpPolicy::RiskyNetwork->settingKey(), 'refuse');
		$bob = $this->user('ids-risky-refuse', null);
		$this->network(['hosting']);
		$this->login($bob);
		$this->assertSame(StepUpState::REFUSED, $this->stepUp()?->status);
		$this->assertCount(1, $this->detectionsOf(StepUpRefused::ID));
	}

	public function testObserveRecordsAndAsksNothing(): void {
		$this->settingsEditor()->setMode(RiskyNetwork::ID, Mode::Observe);
		$this->network(['hosting']);
		$this->login($this->alice);
		$this->assertNull($this->stepUp());
		$detection = $this->detectionsOf(RiskyNetwork::ID)[0];
		$this->assertFalse($detection->isEnforced());
		$this->assertSame([['type' => 'step_up', 'enforced' => false]], $detection->getActionList());
	}

	public function testWithoutTheStepUpResponseItIsOnlyRecorded(): void {
		$this->settingsEditor()->setResponses(RiskyNetwork::ID, [ResponseType::NotifyAdmin]);
		$this->network(['hosting']);
		$this->login($this->alice);
		$this->assertNull($this->stepUp());
		$this->assertCount(1, $this->detectionsOf(RiskyNetwork::ID));
	}

	public function testTheUserCanBeToldInTheirWords(): void {
		$this->settingsEditor()->setResponses(RiskyNetwork::ID, [ResponseType::StepUp, ResponseType::NotifyUser]);
		$this->network(['tor']);
		$this->login($this->alice);
		$this->assertCount(1, $this->notificationsFor($this->alice->getUID(), UserAlerts::SUBJECT));
		$l = Server::get(IFactory::class)->get(Application::APP_ID, 'en');
		$notice = Server::get(RiskyNetwork::class)->userNotice($this->detectionsOf(RiskyNetwork::ID)[0], $l);
		$this->assertSame('Login from a hosting or Tor network', $notice->subject);
		$this->assertSame(['Someone logged in to your account with your password from 198.51.100.7, an address of the Tor network.'], $notice->message);
	}

	public function testAppsSendingThePasswordAreRecordedOnceADay(): void {
		$this->network(['hosting']);
		$this->basicAuth($this->alice);
		for ($i = 0; $i < 3; $i++) {
			$this->session->clear();
			$this->session->id = null;
			$this->login($this->alice);
			$this->assertSame(StepUpState::REFUSED_CLIENT, $this->stepUp()?->status, 'Refused: the account can confirm in a browser, so the app must use an app password');
		}
		$detections = $this->detectionsOf(RiskyNetwork::ID);
		$this->assertCount(1, $detections);
		$this->assertSame(1, $detections[0]->getHits(), 'Later requests do not even touch the database');
		$this->assertTrue($detections[0]->getExplanationData()['facts']['client']);
	}

	public function testAppsSendingThePasswordFromAnotherAddressAreRecordedSeparately(): void {
		$this->network(['hosting']);
		$this->basicAuth($this->alice);
		foreach (['198.51.100.7', '203.0.113.9', '198.51.100.7'] as $address) {
			$this->remoteAddress = $address;
			$this->session->clear();
			$this->session->id = null;
			$this->login($this->alice);
		}
		$detections = $this->detectionsOf(RiskyNetwork::ID);
		$this->assertEqualsCanonicalizing(['198.51.100.7', '203.0.113.9'], array_map(static fn ($d): ?string => $d->getIp(), $detections));
	}

	public function testLoginsFromTwoAddressesAreTwoDetections(): void {
		$this->network(['hosting']);
		$this->login($this->alice);
		$this->session->clear();
		$this->session->id = null;
		$this->remoteAddress = '203.0.113.9';
		$this->login($this->alice);
		$detections = $this->detectionsOf(RiskyNetwork::ID);
		$this->assertCount(2, $detections, 'A "Was this you?" answer applies to one address only');
		$this->assertEqualsCanonicalizing(['198.51.100.7', '203.0.113.9'], array_map(static fn ($d): ?string => $d->getIp(), $detections));
	}

	public function testALoginAfterAnAnswerStartsANewDetection(): void {
		$this->network(['hosting']);
		$this->login($this->alice);
		[$answered] = $this->detectionsOf(RiskyNetwork::ID);
		$this->assertTrue(Server::get(DetectionMapper::class)->setVerdict($answered->getId(), $this->alice->getUID(), \OCA\IntrusionDetection\Db\Detection::VERDICT_CONFIRMED, time()));
		$this->session->clear();
		$this->session->id = null;
		$this->login($this->alice);
		$detections = $this->detectionsOf(RiskyNetwork::ID);
		$this->assertCount(2, $detections, 'The answered detection stays as it was answered');
		$byId = [];
		foreach ($detections as $detection) {
			$byId[$detection->getId()] = $detection;
		}
		$this->assertSame(1, $byId[$answered->getId()]->getHits());
		$this->assertSame(\OCA\IntrusionDetection\Db\Detection::VERDICT_CONFIRMED, $byId[$answered->getId()]->getUserVerdict());
	}

	public function testAHighRiskScoreAsksForConfirmation(): void {
		$this->settingsEditor()->setGlobal(GlobalSettings::RISK_ENABLED, true);
		$this->settingsEditor()->setMode(RiskyNetwork::ID, Mode::Off);
		$this->network(['tor', 'hosting', 'list:watch']);
		$this->login($this->alice);
		$this->assertSame([StepUpPolicy::RiskHigh->value], $this->stepUp()?->policies, 'Score 5: high');
	}

	public function testAHighRiskScoreDoesNotAskWhileLearningOrFromATrustedNetwork(): void {
		$this->settingsEditor()->setGlobal(GlobalSettings::RISK_ENABLED, true);
		$this->settingsEditor()->setMode(RiskyNetwork::ID, Mode::Off);
		$this->network(['tor', 'hosting', 'list:watch']);
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::LEARNING_UNTIL, time() + 86400);
		$this->login($this->alice);
		$this->assertNull($this->stepUp(), 'Learning: nothing acts yet');

		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::LEARNING_UNTIL, 0);
		Server::get(TrustedNetworks::class)->trust($this->alice->getUID(), SourceKey::fromIp($this->remoteAddress));
		$this->session->id = null;
		$this->login($this->alice);
		$this->assertNull($this->stepUp(), 'The user said it was them on this network');

		$bob = $this->user('ids-risky-bob', 'bob@example.com');
		$this->session->id = null;
		$this->login($bob);
		$this->assertSame([StepUpPolicy::RiskHigh->value], $this->stepUp()?->policies, 'Trusted for Alice only');
	}

	public function testAHighRiskScoreWithoutAWayToConfirmIsRefused(): void {
		$this->settingsEditor()->setGlobal(GlobalSettings::RISK_ENABLED, true);
		Server::get(FlaggedSources::class)->flagAttackTool(SourceKey::fromIp($this->remoteAddress), 'hydra');
		Server::get(FlaggedSources::class)->flagNetwork(SourceKey::fromIp($this->remoteAddress), FlaggedSources::REASON_USER_DENIED);
		$this->context->setVerdict(new Verdict());
		$bob = $this->user('ids-risky-high', null);
		$this->login($bob);
		$this->assertSame(StepUpState::REFUSED, $this->stepUp()?->status);
		$this->assertContains(StepUpPolicy::RiskHigh->value, $this->stepUp()?->policies ?? []);
	}

	public function testAnElevatedScoreOrTheScoreOffDoesNotAsk(): void {
		$this->settingsEditor()->setMode(RiskyNetwork::ID, Mode::Off);
		$this->network(['tor', 'hosting']);
		$this->login($this->alice);
		$this->assertNull($this->stepUp(), 'Off');
		$this->settingsEditor()->setGlobal(GlobalSettings::RISK_ENABLED, true);
		$this->session->id = null;
		$this->login($this->alice);
		$this->assertNull($this->stepUp(), 'Score 3 is elevated, not high');
	}

	/**
	 * @param list<string> $attributes
	 */
	private function network(array $attributes): void {
		$this->context->setVerdict(new Verdict(0, '', $attributes));
	}

	#[\Override]
	protected function stepUpReasons(): StepUpReasons {
		$networks = $this->networks();
		return new StepUpReasons(new OverridingContainer([
			RiskyNetworkReason::class => new RiskyNetworkReason($this->checkSettings(), $networks),
			RiskHighReason::class => new RiskHighReason($this->scorer(), $this->appSettings(), Server::get(ITrustedNetworks::class)),
		]), Server::get(LoggerInterface::class));
	}

	#[\Override]
	protected function listenerServices(): array {
		$this->detector ??= new RiskyNetworkDetector(
			$this->checkSettings(),
			$this->networks(),
			Server::get(SourceRepository::class),
			$this->engine(),
			$this->memory(),
			Server::get(ITimeFactory::class),
		);
		return [RiskyNetworkDetector::class => $this->detector];
	}

	private function networks(): NetworkAttributes {
		return new NetworkAttributes(
			$this->appSettings(),
			$this->context,
			Server::get(AddressCache::class),
			$this->addresses(),
			Server::get(ITrustedNetworks::class),
			Server::get(IGroupManager::class),
		);
	}

	private function scorer(): RiskScorer {
		return new RiskScorer(
			$this->appSettings(),
			Server::get(FlaggedSources::class),
			Server::get(AttemptMapper::class),
			Server::get(DetectionMapper::class),
			$this->context,
			Server::get(AddressCache::class),
			$this->addresses(),
			new AttackTools(),
			$this->memory(),
			Server::get(ITimeFactory::class),
			Server::get(LoggerInterface::class),
		);
	}

	private function memory(): Caches {
		$cache = new ArrayCache();
		$factory = new FixedCaches($cache);
		return $factory;
	}
}
