<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\Checks\ManualBlock;
use OCA\IntrusionDetection\Check\Checks\SharedAddress;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Db\KeyLock;
use OCA\IntrusionDetection\Db\LoginMapper;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Detection\DetectionAccounts;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Detection\DetectionService;
use OCA\IntrusionDetection\Detection\DetectionTotals;
use OCA\IntrusionDetection\Event\TypedEvents;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Notification\AdminAlerts;
use OCA\IntrusionDetection\Response\Handlers\BanHandler;
use OCA\IntrusionDetection\Response\Handlers\LockLinkHandler;
use OCA\IntrusionDetection\Response\IResponseHandler;
use OCA\IntrusionDetection\Response\ResponseContext;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCA\IntrusionDetection\Response\ResponseOutcome;
use OCA\IntrusionDetection\Risk\RiskScorer;
use OCP\AppFramework\Db\Entity;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IUser;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/**
 * Uses the internal `manual` check, whose only response is a ban, so the
 * engine can be tested without depending on any real check.
 */
#[Group('DB')]
class ResponseEngineTest extends IntegrationTestCase {
	use CreatesAccounts;

	private ResponseEngine $engine;
	private Settings $settings;
	private DetectionMapper $detections;
	private BanMapper $bans;

	protected function setUp(): void {
		parent::setUp();
		$this->engine = Server::get(ResponseEngine::class);
		$this->settings = Server::get(Settings::class);
		$this->detections = Server::get(DetectionMapper::class);
		$this->bans = Server::get(BanMapper::class);
	}

	protected function tearDown(): void {
		$this->deleteAccounts();
		parent::tearDown();
	}

	public function testProtectRecordsTheDetectionAndActs(): void {
		$detection = $this->engine->handle($this->draft('198.51.100.7'));
		$this->assertNotNull($detection);
		$this->assertTrue($detection->isEnforced());
		$this->assertSame(ManualBlock::ID, $detection->getCheckId());
		$actions = $detection->getActionList();
		$this->assertSame('ban', $actions[0]['type']);
		$this->assertTrue($actions[0]['enforced']);
		$this->assertCount(1, $this->bans->findActiveForKeys(['198.51.100.7'], time()));
	}

	public function testObserveRecordsWhatWouldHaveBeenDone(): void {
		$this->settings->setMode(ManualBlock::ID, Mode::Observe);
		$detection = $this->engine->handle($this->draft('198.51.100.7'));
		$this->assertFalse($detection->isEnforced());
		$this->assertSame([['type' => 'ban', 'enforced' => false]], $detection->getActionList());
		$this->assertSame([], $this->bans->findActiveForKeys(['198.51.100.7'], time()));
	}

	public function testLearningModeObservesAndSaysWhy(): void {
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::LEARNING_UNTIL, time() + 86400);
		$detection = $this->engine->handle($this->draft('198.51.100.7'));
		$this->assertFalse($detection->isEnforced());
		$this->assertSame('learning', $detection->getExplanationData()['mode']['reason']);
		$this->assertSame([], $this->bans->findActiveForKeys(['198.51.100.7'], time()));

		$l = Server::get(IFactory::class)->get('intrusion_detection', 'en');
		$narrative = Server::get(NarrativeBuilder::class)->build($detection, $l);
		$this->assertStringContainsString('learning mode', (string)$narrative->observedBecause);
		$this->assertNotSame([], $narrative->done);
		$this->assertStringStartsNotWith('Would have', $narrative->done[0]);

		$admin = $this->createMock(IUser::class);
		$admin->method('getUID')->willReturn('admin');
		$this->assertSame('What Nextcloud would have done:', Server::get(AdminAlerts::class)->mailFor($detection, $admin)->listHeading);
	}

	public function testOffRecordsNothing(): void {
		$this->settings->setMode(ManualBlock::ID, Mode::Off);
		$this->assertNull($this->engine->handle($this->draft('198.51.100.7')));
		$this->assertSame(0, $this->detections->count(new DetectionFilter()));
	}

	public function testRepeatedHitsFromOneSourceMergeIntoOneDetection(): void {
		$first = $this->engine->handle($this->draft('198.51.100.7', DetectionDraft::MERGE_SOURCE));
		$second = $this->engine->handle($this->draft('198.51.100.7', DetectionDraft::MERGE_SOURCE));
		$this->assertSame($first->getId(), $second->getId());
		$this->assertSame(2, $second->getHits());
		$this->assertSame(1, $this->detections->count(new DetectionFilter()));
		// The merged hit still shows the ban as done, not as "would have".
		$this->assertTrue($second->getActionList()[0]['enforced']);
	}

	public function testAMergedHitWhoseActionsStayTheSameWritesTheDetectionOnce(): void {
		$this->engine->handle($this->draft('198.51.100.7', DetectionDraft::MERGE_SOURCE));
		// The second hit finds the address blocked already: its actions say so.
		$updates = $this->detectionUpdates(fn () => $this->engine->handle($this->draft('198.51.100.7', DetectionDraft::MERGE_SOURCE)));
		$this->assertSame(2, $updates);
		$updates = $this->detectionUpdates(fn () => $this->engine->handle($this->draft('198.51.100.7', DetectionDraft::MERGE_SOURCE)));
		$this->assertSame(1, $updates, 'the hit, not the unchanged actions');
		$updates = $this->detectionUpdates(fn () => $this->engine->handle($this->draft('198.51.100.9', DetectionDraft::MERGE_SOURCE)));
		$this->assertSame(1, $updates, 'a new detection: its actions once after the insert');
	}

	/**
	 * @param \Closure(): mixed $hit
	 */
	private function detectionUpdates(\Closure $hit): int {
		$counting = new class($this->db) extends DetectionMapper {
			public int $updates = 0;

			public function update(Entity $entity): Entity {
				$this->updates++;
				return parent::update($entity);
			}
		};
		$this->engine = new ResponseEngine(
			Server::get(CheckRegistry::class),
			$this->settings,
			new DetectionService(
				$counting,
				Server::get(CheckRegistry::class),
				$this->settings,
				Server::get(ITimeFactory::class),
				Server::get(RiskScorer::class),
				Server::get(DetectionAccounts::class),
				Server::get(DetectionTotals::class),
				Server::get(KeyLock::class),
			),
			Server::get(ContainerInterface::class),
			Server::get(TypedEvents::class),
			Server::get(AuditLogger::class),
			Server::get(LoggerInterface::class),
		);
		$hit();
		return $counting->updates;
	}

	public function testAMergedHitKeepsTheEarlierFacts(): void {
		$first = $this->engine->handle(new DetectionDraft(ManualBlock::ID, SourceKey::fromIp('198.51.100.7'), facts: ['rule' => 'a', 'targets' => ['alice', 'bob'], 'first' => 1000, 'last' => 1100], merge: DetectionDraft::MERGE_SOURCE));
		$second = $this->engine->handle(new DetectionDraft(ManualBlock::ID, SourceKey::fromIp('198.51.100.7'), facts: ['rule' => 'a', 'targets' => ['carol'], 'first' => 1050, 'last' => 1200], merge: DetectionDraft::MERGE_SOURCE));
		$this->assertSame($first?->getId(), $second?->getId());
		$facts = $this->detections->findById($second->getId())->getExplanationData()['facts'];
		$this->assertSame(['alice', 'bob', 'carol'], $facts['targets']);
		$this->assertSame(1000, $facts['first']);
		$this->assertSame(1200, $facts['last']);
	}

	public function testAResponseForNewDetectionsOnlyIsNotRunAgainForAMergedHit(): void {
		$handler = new class implements IResponseHandler {
			/** @var list<bool> isNew of every run */
			public array $runs = [];

			public function type(): ResponseType {
				return ResponseType::Ban;
			}

			public function apply(ResponseContext $context): ResponseOutcome {
				$this->runs[] = $context->isNew;
				return ResponseOutcome::done(['run' => count($this->runs)]);
			}
		};
		$engine = new ResponseEngine(
			Server::get(CheckRegistry::class),
			$this->settings,
			Server::get(DetectionService::class),
			new OverridingContainer([BanHandler::class => $handler]),
			Server::get(TypedEvents::class),
			Server::get(AuditLogger::class),
			Server::get(LoggerInterface::class),
		);
		$draft = function (): DetectionDraft {
			$draft = $this->draft('198.51.100.7', DetectionDraft::MERGE_SOURCE);
			$draft->runOnlyWhenNew(ResponseType::Ban);
			return $draft;
		};
		$first = $engine->handle($draft());
		$second = $engine->handle($draft());
		$this->assertSame($first?->getId(), $second?->getId());
		$this->assertSame([true], $handler->runs, 'Run for the new detection only');
		$this->assertSame([['type' => 'ban', 'enforced' => true, 'ref' => ['run' => 1]]], $second->getActionList(), 'What was done first is kept');

		$engine->handle($this->draft('198.51.100.7', DetectionDraft::MERGE_SOURCE));
		$this->assertSame([true, false], $handler->runs, 'Other drafts run it for merged hits as before');
	}

	public function testHitsOfAnotherRuleAreAnotherDetection(): void {
		$this->engine->handle(new DetectionDraft(ManualBlock::ID, SourceKey::fromIp('198.51.100.7'), facts: ['rule' => 'a'], merge: DetectionDraft::MERGE_SOURCE));
		$this->engine->handle(new DetectionDraft(ManualBlock::ID, SourceKey::fromIp('198.51.100.7'), facts: ['rule' => 'b'], merge: DetectionDraft::MERGE_SOURCE));
		$rules = array_map(static fn ($d): string => $d->getExplanationData()['facts']['rule'], $this->detections->findList(new DetectionFilter()));
		$this->assertEqualsCanonicalizing(['a', 'b'], $rules);
	}

	public function testDifferentSourcesAreSeparateDetections(): void {
		$this->engine->handle($this->draft('198.51.100.7', DetectionDraft::MERGE_SOURCE));
		$this->engine->handle($this->draft('198.51.100.8', DetectionDraft::MERGE_SOURCE));
		$this->assertSame(2, $this->detections->count(new DetectionFilter()));
	}

	public function testAResponseWithoutAHandlerIsRecordedAsUnavailable(): void {
		$engine = new ResponseEngine(
			Server::get(CheckRegistry::class),
			$this->settings,
			Server::get(DetectionService::class),
			new OverridingContainer([LockLinkHandler::class => new \stdClass()]),
			Server::get(TypedEvents::class),
			Server::get(AuditLogger::class),
			Server::get(LoggerInterface::class),
		);
		$detection = $engine->handle(new DetectionDraft(SharedAddress::ID, SourceKey::fromIp('198.51.100.7')), [ResponseType::LockLink]);
		$this->assertSame([['type' => 'lock_link', 'enforced' => false, 'note' => ResponseOutcome::NOTE_UNAVAILABLE]], $detection->getActionList());
	}

	public function testTheSafetyValveRaisesASharedAddressDetectionInsteadOfABan(): void {
		$source = SourceKey::fromIp('198.51.100.7');
		$logins = Server::get(LoginMapper::class);
		foreach ($this->accounts(5) as $uid) {
			$logins->record($source->ipKey, $source->netKey, $uid, intdiv(time(), 3600));
		}
		$detection = $this->engine->handle($this->draft('198.51.100.7'));
		$this->assertSame(ResponseOutcome::NOTE_NOTHING_TO_DO, $detection->getActionList()[0]['note'] ?? null);
		$shared = $this->detections->findList(new DetectionFilter(checkIds: [SharedAddress::ID]));
		$this->assertCount(1, $shared);
		$this->assertSame(5, $shared[0]->getExplanationData()['facts']['users']);
		$this->assertSame(ManualBlock::ID, $shared[0]->getExplanationData()['facts']['wantedBy']);
	}

	public function testExplanationKeepsTheThresholdsAndCleansTheUserAgent(): void {
		$detection = $this->engine->handle(new DetectionDraft(
			ManualBlock::ID,
			SourceKey::fromIp('198.51.100.7'),
			facts: ['targets' => array_map(static fn (int $i): string => 'user' . $i, range(1, 30))],
			userAgent: "curl/8.0\n\x07" . str_repeat('x', 300),
		));
		$explanation = $detection->getExplanationData();
		$this->assertCount(20, $explanation['facts']['targets']);
		$this->assertSame(200, mb_strlen($explanation['userAgent']));
		$this->assertStringNotContainsString("\n", $explanation['userAgent']);
		$this->assertSame('198.51.100.0/24', $explanation['source']['net']);
	}

	private function draft(string $ip, string $merge = DetectionDraft::MERGE_NONE): DetectionDraft {
		return new DetectionDraft(ManualBlock::ID, SourceKey::fromIp($ip), merge: $merge);
	}
}
