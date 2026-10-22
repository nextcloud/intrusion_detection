<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Check;

use OCA\IntrusionDetection\Check\Checks\ResetProbing;
use OCA\IntrusionDetection\Check\Checks\ResetProbingDetector;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Db\AttemptMapper;
use OCA\IntrusionDetection\Db\AttemptStats;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Detection\AttemptRecord;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCA\IntrusionDetection\Risk\RiskLimits;
use OCA\IntrusionDetection\Risk\RiskScorer;
use OCP\IDateTimeFormatter;
use Test\TestCase;

class ResetProbingDetectorTest extends TestCase {
	private const ALL = [ResponseType::Ban, ResponseType::SuppressResetMail, ResponseType::NotifyAdmin, ResponseType::NotifyUser];

	/** @var list<list<ResponseType>> */
	private array $handled = [];
	/** @var list<DetectionDraft> */
	private array $drafts = [];
	private int $sampleFactor = 1;
	private int $requests = 5;

	public function testTheUserIsToldWhenAFloodBeginsAndNotForEveryLaterRequest(): void {
		$this->detector()->detect($this->attempt(), null);
		$this->assertSame([[ResponseType::SuppressResetMail, ResponseType::NotifyAdmin, ResponseType::NotifyUser]], $this->handled);
		$this->assertCount(1, $this->drafts);
		$this->assertTrue($this->drafts[0]->runsOnlyWhenNew(ResponseType::NotifyUser), 'A request that continues the flood does not tell the user again');
		$this->assertFalse($this->drafts[0]->runsOnlyWhenNew(ResponseType::SuppressResetMail), 'It keeps holding back the emails');
	}

	public function testUnderAFloodAFewKeptRequestsNeverFire(): void {
		$this->sampleFactor = 10;
		$this->requests = 2;
		$this->detector()->detect($this->attempt(), null);
		$this->assertSame([], $this->handled, 'Two kept requests stand for 20, but are too few to judge');

		$this->requests = 3;
		$this->detector()->detect($this->attempt(), null);
		$this->assertCount(1, $this->handled);
	}

	public function testAnAttemptTheRecorderDidNotKeepIsNotEvaluated(): void {
		$this->detector()->detect(new AttemptRecord(AttemptKind::PasswordReset, SourceKey::fromIp('198.51.100.7'), 'aa', 'alice', null, null, [], time(), false), null);
		$this->assertSame([], $this->handled);
	}

	private function detector(): ResetProbingDetector {
		$settings = $this->createMock(Settings::class);
		$settings->method('modeState')->willReturn(new ModeState(Mode::Protect, Mode::Protect));
		$settings->method('params')->willReturn(['enum_min_inputs' => 5, 'enum_window' => 600, 'flood_min_requests' => 5, 'flood_window' => 3600, 'suppress_duration' => 3600]);
		$settings->method('responses')->willReturn(self::ALL);
		$attempts = $this->createMock(AttemptMapper::class);
		$attempts->method('stats')->willReturnCallback(fn (string $column): AttemptStats => $column === 'uid'
			? new AttemptStats(failures: $this->requests, distinctNames: 1, distinctSources: $this->requests, first: time() - 60, last: time(), estimatedFailures: $this->requests * $this->sampleFactor, maxWeight: $this->sampleFactor)
			: new AttemptStats(failures: 1, distinctNames: 1, distinctSources: 1));
		$engine = $this->createMock(ResponseEngine::class);
		$engine->method('handle')->willReturnCallback(function (DetectionDraft $draft, ?array $responses = null): ?Detection {
			$this->assertSame(ResetProbing::RULE_FLOOD, $draft->facts['rule']);
			$this->assertSame($this->requests * $this->sampleFactor, $draft->facts['requests']);
			$this->handled[] = $responses ?? [];
			$this->drafts[] = $draft;
			return null;
		});
		$risk = $this->createMock(RiskScorer::class);
		$risk->method('limits')->willReturnCallback(static function (?SourceKey $source, array $limits): RiskLimits {
			$plain = array_map(static fn (array $l): int => $l[0], $limits);
			return new RiskLimits($plain, $plain, array_map(static fn (array $l): int => $l[1], $limits), null);
		});
		return new ResetProbingDetector($settings, $attempts, $engine, new ResetProbing(DateFormatter::using($this->createMock(IDateTimeFormatter::class))), $risk);
	}

	private function attempt(): AttemptRecord {
		return new AttemptRecord(AttemptKind::PasswordReset, SourceKey::fromIp('198.51.100.7'), 'aa', 'alice', null, null, [], time(), true);
	}
}
