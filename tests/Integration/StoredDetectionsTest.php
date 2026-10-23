<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\Checks\ManualBlock\ManualBlock;
use OCA\IntrusionDetection\Check\Checks\StepUpFailed\StepUpFailed;
use OCA\IntrusionDetection\Check\Checks\StepUpRefused\StepUpRefused;
use OCA\IntrusionDetection\Check\Checks\StepUpRefusedClient\StepUpRefusedClient;
use OCA\IntrusionDetection\Check\Checks\StepUpUnconfirmed\StepUpUnconfirmed;
use OCA\IntrusionDetection\Check\ISimulatable;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Detection\FactsMerger;
use OCA\IntrusionDetection\Detection\IFacts;
use OCA\IntrusionDetection\Detection\IMergeableFacts;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Explain\IAsksWasThisYou;
use OCA\IntrusionDetection\Explain\IExplainsDetection;
use OCA\IntrusionDetection\Explain\IExplainsToUser;
use OCA\IntrusionDetection\Explain\IHeadlinesDetection;
use OCA\IntrusionDetection\Explain\IKeepsFromUser;
use OCA\IntrusionDetection\Net\SourceKey;
use OCP\IDateTimeFormatter;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use Test\TestCase;

/**
 * Detections stored in the format of their check's facts read as they did
 * when they were stored, and repeated hits merge into the same facts.
 * The fixtures in `tests/fixtures/stored-detections/` hold rows of every
 * check's rules, rows written before some facts existed, and what the
 * check said about them.
 */
#[Group('DB')]
class StoredDetectionsTest extends TestCase {
	public const NOW = 1790000000;
	private const FIXTURES = __DIR__ . '/../fixtures/stored-detections/';

	/** Checks without a facts class, and why. This list may only shrink. */
	private const UNTYPED = [
		ManualBlock::ID => 'records no detections',
		StepUpFailed::ID => 'its drafts still give an array, which merges by shape',
		StepUpRefused::ID => 'its drafts still give an array, which merges by shape',
		StepUpRefusedClient::ID => 'its drafts still give an array, which merges by shape',
		StepUpUnconfirmed::ID => 'its drafts still give an array, which merges by shape',
	];

	public function testEveryCheckHasAFactsClass(): void {
		$untyped = [];
		foreach (Server::get(CheckRegistry::class)->all() as $definition) {
			if (self::factsClass($definition->id) === null) {
				$untyped[] = $definition->id;
			}
		}
		sort($untyped);
		$listed = array_keys(self::UNTYPED);
		sort($listed);
		$this->assertSame($listed, $untyped, 'Give the check a <Name>Facts class in its folder, or remove it from UNTYPED once it has one');
	}

	/**
	 * @return \Generator<string, array{string, array<string, mixed>, array<string, mixed>}>
	 */
	public static function storedRows(): \Generator {
		foreach (self::fixture('rows.json') as $checkId => $cases) {
			foreach ($cases as $name => $case) {
				yield $checkId . ': ' . $name => [$checkId, $case['detection'], $case['reads']];
			}
		}
	}

	/**
	 * @param array<string, mixed> $row
	 * @param array<string, mixed> $reads
	 */
	#[DataProvider('storedRows')]
	public function testAStoredDetectionReadsAsItDidWhenItWasStored(string $checkId, array $row, array $reads): void {
		$this->assertSame($reads, $this->reads(self::detection($row)));
	}

	/**
	 * @return \Generator<string, array{string, array<string, mixed>, array<string, mixed>, array<string, mixed>}>
	 */
	public static function merges(): \Generator {
		foreach (self::fixture('merges.json') as $checkId => $cases) {
			foreach ($cases as $i => $case) {
				yield $checkId . ' #' . $i => [$checkId, $case['stored'], $case['hit'], $case['merged']];
			}
		}
	}

	/**
	 * @param array<string, mixed> $stored
	 * @param array<string, mixed> $hit
	 * @param array<string, mixed> $merged
	 */
	#[DataProvider('merges')]
	public function testARepeatedHitMergesIntoTheStoredFactsAsBefore(string $checkId, array $stored, array $hit, array $merged): void {
		$this->assertSame(self::canonical($merged), self::canonical(self::merge($checkId, $stored, $hit)));
	}

	/**
	 * @param array<string, mixed> $stored
	 * @param array<string, mixed> $hit
	 * @param array<string, mixed> $merged
	 */
	#[DataProvider('merges')]
	public function testTheFactsClassKeepsTheStoredShape(string $checkId, array $stored, array $hit, array $merged): void {
		$class = self::factsClass($checkId);
		$this->assertNotNull($class);
		$this->assertTrue(is_a($class, IMergeableFacts::class, true), 'The facts of a check whose hits merge declare how');
		// Stored rows may predate a fact; the facts of a hit and of a merge have today's shape.
		foreach ([$hit, $merged] as $facts) {
			$this->assertSame(self::canonical($facts), self::canonical($class::fromArray($facts)->toArray()));
		}
	}

	public function testASimulationStoresTheFactsItDidBefore(): void {
		$this->assertSame(self::fixture('simulations.json'), $this->simulations());
	}

	/**
	 * The facts of a repeated hit merged into stored facts.
	 *
	 * @param array<string, mixed> $stored
	 * @param array<string, mixed> $hit
	 * @return array<string, mixed>
	 */
	public static function merge(string $checkId, array $stored, array $hit): array {
		$class = self::factsClass($checkId);
		return FactsMerger::merge($stored, new DetectionDraft(checkId: $checkId, facts: $class === null ? $hit : $class::fromArray($hit)));
	}

	/**
	 * The facts class of a check, `<Name>Facts` in its folder.
	 *
	 * @return ?class-string<IFacts>
	 */
	public static function factsClass(string $checkId): ?string {
		$class = Server::get(CheckRegistry::class)->classOf($checkId) . 'Facts';
		return class_exists($class) ? $class : null;
	}

	/**
	 * The facts every simulatable check simulates with its default parameters.
	 *
	 * @return array<string, array<string, mixed>>
	 */
	public function simulations(): array {
		$registry = Server::get(CheckRegistry::class);
		$source = SourceKey::fromIp('203.0.113.5');
		$facts = [];
		foreach ($registry->all() as $definition) {
			$check = $this->check($registry->classOf($definition->id));
			if (!$check instanceof ISimulatable) {
				continue;
			}
			$params = [];
			foreach ($definition->params as $param) {
				$params[$param->name] = $param->default;
			}
			$facts[$definition->id] = self::canonical($check->simulate($source, self::NOW, $params)->facts);
		}
		ksort($facts);
		return $facts;
	}

	/**
	 * Everything a check says about a stored detection.
	 *
	 * @return array<string, mixed>
	 */
	public function reads(Detection $detection): array {
		$l = Server::get(IFactory::class)->get('intrusion_detection', 'en');
		$check = $this->check(Server::get(CheckRegistry::class)->classOf((string)$detection->getCheckId()));
		$reads = [];
		if ($check instanceof IExplainsDetection) {
			$reads['narrative'] = $check->narrative($detection, $l);
		}
		if ($check instanceof IHeadlinesDetection) {
			$reads['headline'] = $check->headline($detection, $l);
		}
		if ($check instanceof IExplainsToUser) {
			$notice = $check->userNotice($detection, $l);
			$reads['userNotice'] = ['subject' => $notice->subject, 'message' => $notice->message, 'advice' => $notice->advice];
		}
		if ($check instanceof IAsksWasThisYou) {
			$reads['asksWasThisYou'] = $check->asksWasThisYou($detection);
		}
		if ($check instanceof IKeepsFromUser) {
			$reads['keepsFromUser'] = $check->keepsFromUser($detection);
		}
		return $reads;
	}

	/**
	 * @param array<string, mixed> $row
	 */
	public static function detection(array $row): Detection {
		$detection = new Detection();
		$detection->setId($row['id']);
		$detection->setCheckId($row['checkId']);
		$detection->setSeverity($row['severity']);
		$detection->setEnforced($row['enforced']);
		$detection->setIp($row['ip']);
		$detection->setNetKey($row['netKey']);
		$detection->setUid($row['uid']);
		$detection->setShareId($row['shareId']);
		$detection->setHits($row['hits']);
		$detection->setCreatedAt($row['createdAt']);
		$detection->setLastSeenAt($row['lastSeenAt']);
		$detection->setActionList($row['actions']);
		$detection->setExplanationData($row['explanation']);
		return $detection;
	}

	/**
	 * A check built with dates that read as "date:<timestamp>" and "time:<timestamp>".
	 *
	 * @param class-string $class
	 */
	private function check(string $class): object {
		$formatter = $this->createMock(IDateTimeFormatter::class);
		$formatter->method('formatDateTime')->willReturnCallback(static fn (int $timestamp): string => 'date:' . $timestamp);
		$formatter->method('formatTime')->willReturnCallback(static fn (int $timestamp): string => 'time:' . $timestamp);
		$constructor = (new \ReflectionClass($class))->getConstructor();
		$arguments = [];
		foreach ($constructor?->getParameters() ?? [] as $parameter) {
			$type = (string)$parameter->getType();
			$arguments[] = $type === DateFormatter::class ? DateFormatter::using($formatter) : Server::get($type);
		}
		return new $class(...$arguments);
	}

	/**
	 * @return array<array-key, mixed>
	 */
	public static function fixture(string $name): array {
		return json_decode((string)file_get_contents(self::FIXTURES . $name), true, 64, JSON_THROW_ON_ERROR);
	}

	/**
	 * The value with the keys of its maps sorted: the order of stored keys carries no meaning.
	 */
	public static function canonical(mixed $value): mixed {
		if (!is_array($value)) {
			return $value;
		}
		$value = array_map(self::canonical(...), $value);
		if (!array_is_list($value)) {
			ksort($value);
		}
		return $value;
	}
}
