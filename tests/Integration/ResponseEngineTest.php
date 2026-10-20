<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\ManualBlock;
use OCA\IntrusionDetection\Check\Checks\SharedAddress;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Db\LoginMapper;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCA\IntrusionDetection\Response\ResponseOutcome;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * Uses the internal `manual` check, whose only response is a ban, so the
 * engine can be tested without depending on any real check.
 */
#[Group('DB')]
class ResponseEngineTest extends IntegrationTestCase {
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
		$this->assertStringStartsWith('Would have', $narrative->done[0]);
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

	public function testDifferentSourcesAreSeparateDetections(): void {
		$this->engine->handle($this->draft('198.51.100.7', DetectionDraft::MERGE_SOURCE));
		$this->engine->handle($this->draft('198.51.100.8', DetectionDraft::MERGE_SOURCE));
		$this->assertSame(2, $this->detections->count(new DetectionFilter()));
	}

	public function testAResponseWithoutAHandlerIsRecordedAsUnavailable(): void {
		$detection = $this->engine->handle(new DetectionDraft(SharedAddress::ID, SourceKey::fromIp('198.51.100.7')), [ResponseType::NotifyAdmin]);
		$this->assertSame([['type' => 'notify_admin', 'enforced' => false, 'note' => ResponseOutcome::NOTE_UNAVAILABLE]], $detection->getActionList());
	}

	public function testTheSafetyValveRaisesASharedAddressDetectionInsteadOfABan(): void {
		$source = SourceKey::fromIp('198.51.100.7');
		$logins = Server::get(LoginMapper::class);
		foreach (['alice', 'bob', 'carol', 'dave', 'erin'] as $uid) {
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
