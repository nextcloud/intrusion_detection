<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\Checks\PasswordSpraying\PasswordSpraying;
use OCA\IntrusionDetection\Check\Checks\PasswordSpraying\PasswordSprayingRule;
use OCA\IntrusionDetection\Check\Checks\SharedAddress\SharedAddress;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Response\ResponseOutcome;
use OCA\IntrusionDetection\Risk\RiskExplainer;
use OCP\IDateTimeFormatter;
use OCP\IL10N;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Container\ContainerInterface;
use Test\TestCase;

/**
 * How a stored detection becomes "what happened, and what Nextcloud did":
 * the check's own sentences or the generic ones, the risk sentence after
 * them, one sentence per action, and why nothing was done.
 */
#[Group('DB')]
class NarrativeBuilderTest extends TestCase {
	private const NOW = 1790000000;

	private NarrativeBuilder $builder;
	private IL10N $l;

	protected function setUp(): void {
		parent::setUp();
		$formatter = $this->createMock(IDateTimeFormatter::class);
		$formatter->method('formatDateTime')->willReturnCallback(static fn (int $timestamp): string => 'date:' . $timestamp);
		$formatter->method('formatTime')->willReturnCallback(static fn (int $timestamp): string => 'time:' . $timestamp);
		$this->builder = new NarrativeBuilder(
			Server::get(CheckRegistry::class),
			Server::get(ContainerInterface::class),
			DateFormatter::using($formatter),
			Server::get(RiskExplainer::class),
		);
		$this->l = Server::get(IFactory::class)->get('intrusion_detection', 'en');
	}

	public function testACheckWithoutWordsOfItsOwnIsToldFromTheDetection(): void {
		$detection = self::detection(SharedAddress::ID, ['users' => 4], hits: 3);
		$narrative = $this->builder->build($detection, $this->l);

		$texts = Server::get(CheckRegistry::class)->get(SharedAddress::ID)->texts($this->l);
		$this->assertSame($texts->name, $narrative->title);
		$this->assertSame($texts->summary, $narrative->happened[0]);
		$this->assertCount(4, $narrative->happened, 'summary, address, account, how often');
		$this->assertStringContainsString('203.0.113.5', $narrative->happened[1]);
		$this->assertStringContainsString('alice', $narrative->happened[2]);
		$this->assertStringContainsString('date:' . (self::NOW - 300), $narrative->happened[3]);
		$this->assertStringContainsString('date:' . self::NOW, $narrative->happened[3]);
	}

	public function testADetectionOfARetiredCheckIsStillShown(): void {
		$detection = self::detection('retired_check', [], uid: null);
		$narrative = $this->builder->build($detection, $this->l);

		$this->assertSame('retired_check', $narrative->title);
		$this->assertCount(1, $narrative->happened, 'only the address');
		$this->assertStringContainsString('203.0.113.5', $narrative->happened[0]);
	}

	public function testTheChecksOwnSentencesAreFollowedByTheRiskScore(): void {
		$facts = ['rule' => PasswordSprayingRule::Flagged->value, 'names' => 3];
		$plain = $this->builder->build(self::detection(PasswordSpraying::ID, $facts), $this->l);
		$risky = $this->builder->build(self::detection(PasswordSpraying::ID, $facts + [
			'risk' => ['score' => 40, 'tier' => 'elevated', 'factor' => 0.5, 'parts' => [['fact' => 'failures', 'points' => 40, 'detail' => '30']], 'tiers' => ['elevated' => 30, 'high' => 60]],
			'loweredLimits' => ['min_names' => ['plain' => 5, 'effective' => 3]],
		]), $this->l);

		$this->assertCount(1, $plain->happened);
		$this->assertCount(2, $risky->happened);
		$this->assertSame($plain->happened[0], $risky->happened[0]);
		$this->assertStringContainsString('3 instead of 5', $risky->happened[1]);
	}

	public function testEveryActionIsOneSentenceAndThoseNotNeededAreOne(): void {
		$detection = self::detection(SharedAddress::ID, [], actions: [
			['type' => 'retired_response', 'enforced' => true],
			['type' => ResponseType::NotifyAdmin->value, 'enforced' => true, 'note' => ResponseOutcome::NOTE_UNAVAILABLE],
			['type' => ResponseType::NotifyUser->value, 'enforced' => true, 'note' => ResponseOutcome::NOTE_FAILED],
			['type' => ResponseType::FlagSource->value, 'enforced' => true, 'note' => ResponseOutcome::NOTE_NOTHING_TO_DO],
			['type' => ResponseType::RateLimit->value, 'enforced' => true, 'note' => ResponseOutcome::NOTE_NOTHING_TO_DO],
			['type' => ResponseType::StepUp->value, 'enforced' => false],
		]);
		$done = $this->builder->build($detection, $this->l)->done;

		$this->assertCount(4, $done, 'the retired response is left out');
		$this->assertStringContainsString(ResponseType::NotifyAdmin->describe($this->l), $done[0]);
		$this->assertStringContainsString(ResponseType::NotifyUser->describe($this->l), $done[1]);
		$this->assertNotSame($done[0], ResponseType::NotifyAdmin->describe($this->l), 'says that it is not available');
		$this->assertNotSame($done[1], ResponseType::NotifyUser->describe($this->l), 'says that it failed');
		$this->assertSame(ResponseType::StepUp->describe($this->l), $done[2]);
		$this->assertStringContainsString(ResponseType::FlagSource->describe($this->l) . ' ' . ResponseType::RateLimit->describe($this->l), $done[3]);
	}

	public function testADetectionWithoutActionsSaysSo(): void {
		$done = $this->builder->build(self::detection(SharedAddress::ID, []), $this->l)->done;
		$this->assertCount(1, $done);
		$this->assertNotSame('', $done[0]);
	}

	public function testAnObservedDetectionSaysWhyNothingWasDone(): void {
		$this->assertNull($this->builder->build(self::detection(SharedAddress::ID, []), $this->l)->observedBecause);

		$reasons = [];
		foreach ([ModeState::REASON_LEARNING, ModeState::REASON_AUTHENTICATED, null] as $reason) {
			$detection = self::detection(SharedAddress::ID, [], enforced: false, reason: $reason);
			$reasons[] = $this->builder->build($detection, $this->l)->observedBecause;
		}
		$this->assertNotContains(null, $reasons);
		$this->assertCount(3, array_unique($reasons), 'learning mode, a logged-in request and Observe each have their own reason');
	}

	/**
	 * @param array<string, mixed> $facts
	 * @param list<array<string, mixed>> $actions
	 */
	private static function detection(string $checkId, array $facts, int $hits = 1, ?string $uid = 'alice', array $actions = [], bool $enforced = true, ?string $reason = null): Detection {
		$detection = Detection::fromRow(['id' => '41']);
		$detection->setCheckId($checkId);
		$detection->setSeverity('high');
		$detection->setEnforced($enforced);
		$detection->setIp('203.0.113.5');
		$detection->setUid($uid);
		$detection->setHits($hits);
		$detection->setCreatedTime(self::NOW - 300);
		$detection->setLastSeenAt(self::NOW);
		$detection->setActionList($actions);
		$detection->setExplanationData(['mode' => ['configured' => 'protect', 'effective' => 'protect', 'reason' => $reason], 'facts' => $facts]);
		return $detection;
	}
}
