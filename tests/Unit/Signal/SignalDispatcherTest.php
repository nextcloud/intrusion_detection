<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Signal;

use OCA\IntrusionDetection\Check\CheckRegistry;
use OCA\IntrusionDetection\Check\Checks\AccountUnderAttack\AccountUnderAttackDetector;
use OCA\IntrusionDetection\Check\Checks\BlocklistMatch\BlocklistMatch;
use OCA\IntrusionDetection\Check\Checks\BlocklistMatch\BlocklistMatchDetector;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffing\CredentialStuffingDetector;
use OCA\IntrusionDetection\Check\Checks\DecoyCredential\DecoyCredential;
use OCA\IntrusionDetection\Check\Checks\DecoyCredential\DecoyCredentialDetector;
use OCA\IntrusionDetection\Check\Checks\PasswordSpraying\PasswordSprayingDetector;
use OCA\IntrusionDetection\Check\Checks\ReservedName\ReservedNameDetector;
use OCA\IntrusionDetection\Config\CheckSettings;
use OCA\IntrusionDetection\Config\LexiconData;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Detection\AttemptRecord;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCA\IntrusionDetection\Signal\FailedLogin;
use OCA\IntrusionDetection\Signal\FailedLoginAttempt;
use OCA\IntrusionDetection\Signal\IDetector;
use OCA\IntrusionDetection\Signal\ISignal;
use OCA\IntrusionDetection\Signal\SignalDispatcher;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Test\TestCase;

class SignalDispatcherTest extends TestCase {
	/** @var array<string, Mode> */
	private array $modes = [];
	/** @var list<string> */
	private array $built = [];
	/** @var list<string> */
	private array $handled = [];

	public function testEveryDetectorIsListedUnderItsOwnCheck(): void {
		foreach (CheckRegistry::DETECTORS as $signal => $detectors) {
			$this->assertTrue(is_a($signal, ISignal::class, true), $signal);
			foreach ($detectors as $checkId => $class) {
				$this->assertTrue(is_a($class, IDetector::class, true), $class);
				$namespace = substr($class, 0, (int)strrpos($class, '\\'));
				$check = $namespace . substr($namespace, (int)strrpos($namespace, '\\'));
				$this->assertSame($checkId, constant($check . '::ID'), $class . ' is listed under another check');
				$this->assertArrayHasKey($checkId, LexiconData::CHECKS);
			}
		}
	}

	public function testTheDetectorsRunInOrderAndAFinalDraftEndsTheChain(): void {
		$dispatch = $this->dispatcher([
			BlocklistMatchDetector::class => $this->detector([$this->draft(BlocklistMatch::ID)]),
			DecoyCredentialDetector::class => $this->detector([$this->draft(DecoyCredential::ID, final: true)]),
			ReservedNameDetector::class => $this->detector([$this->draft('reserved_name')]),
		])->dispatch($this->failedLogin());

		$this->assertTrue($dispatch->stopped);
		$this->assertCount(2, $dispatch->detections);
		$this->assertSame([BlocklistMatch::ID, DecoyCredential::ID], $this->handled);
		$this->assertSame([BlocklistMatchDetector::class, DecoyCredentialDetector::class], $this->built, 'Nothing after a final draft is built');
	}

	public function testADetectorWhoseCheckDoesNotRunIsNotBuilt(): void {
		$this->modes[DecoyCredential::ID] = Mode::Off;
		$dispatch = $this->dispatcher([
			BlocklistMatchDetector::class => $this->detector([]),
			DecoyCredentialDetector::class => $this->detector([$this->draft(DecoyCredential::ID, final: true)]),
			ReservedNameDetector::class => $this->detector([]),
		])->dispatch($this->failedLogin());

		$this->assertFalse($dispatch->stopped);
		$this->assertSame([BlocklistMatchDetector::class, ReservedNameDetector::class], $this->built);
	}

	public function testAFailingDetectorIsLoggedAndTheNextOneStillRuns(): void {
		$logger = $this->createMock(LoggerInterface::class);
		$logger->expects($this->once())->method('error')->with($this->anything(), $this->callback(
			static fn (array $context): bool => $context['step'] === BlocklistMatch::ID && $context['signal'] === 'FailedLogin' && $context['exception'] instanceof \RuntimeException,
		));
		$failing = $this->createMock(BlocklistMatchDetector::class);
		$failing->method('detect')->willThrowException(new \RuntimeException('database gone'));
		$dispatch = $this->dispatcher([
			BlocklistMatchDetector::class => $failing,
			DecoyCredentialDetector::class => $this->detector([$this->draft(DecoyCredential::ID)]),
			ReservedNameDetector::class => $this->detector([]),
		], $logger)->dispatch($this->failedLogin());

		$this->assertSame([DecoyCredential::ID], $this->handled);
		$this->assertCount(1, $dispatch->detections);
	}

	public function testAGeneratorGetsEachStoredDetectionBack(): void {
		$received = [];
		$generator = new class($received) implements IDetector {
			/** @param list<?Detection> $received */
			public function __construct(
				private array &$received,
			) {
			}

			public function detect(#[\SensitiveParameter] ISignal $signal, ModeState $mode): \Generator {
				$this->received[] = yield new DetectionDraft('password_spraying');
				$this->received[] = yield new DetectionDraft('shared_address');
			}
		};
		$this->modes['shared_address'] = Mode::Off;
		$this->dispatcher([
			PasswordSprayingDetector::class => $generator,
			CredentialStuffingDetector::class => $this->detector([]),
			AccountUnderAttackDetector::class => $this->detector([]),
		])->dispatch(new FailedLoginAttempt($this->attempt(), 'secret', null));

		$this->assertCount(2, $received);
		$this->assertInstanceOf(Detection::class, $received[0]);
		$this->assertNull($received[1], 'The engine stores nothing for a check that is off');
	}

	public function testAGivenModeRunsTheDetectorsWhateverTheirChecks(): void {
		$this->modes[DecoyCredential::ID] = Mode::Off;
		$seen = [];
		$detector = $this->createMock(DecoyCredentialDetector::class);
		$detector->method('detect')->willReturnCallback(static function (ISignal $signal, ModeState $mode) use (&$seen): array {
			$seen[] = $mode->effective;
			return [];
		});
		$this->dispatcher([
			BlocklistMatchDetector::class => $this->detector([]),
			DecoyCredentialDetector::class => $detector,
			ReservedNameDetector::class => $this->detector([]),
		])->dispatch($this->failedLogin(), new ModeState(Mode::Observe, Mode::Observe));

		$this->assertSame([Mode::Observe], $seen);
	}

	public function testWhetherASignalsChecksRunOrAct(): void {
		$dispatcher = $this->dispatcher([]);
		$this->modes = ['password_spraying' => Mode::Off, 'credential_stuffing' => Mode::Observe, 'account_under_attack' => Mode::Off];
		$this->assertTrue($dispatcher->runs(FailedLoginAttempt::class));
		$this->assertFalse($dispatcher->acts(FailedLoginAttempt::class));
		$this->assertFalse($dispatcher->runs(FailedLoginAttempt::class, AccountUnderAttackDetector::class));
		$this->assertTrue($dispatcher->runs(FailedLoginAttempt::class, CredentialStuffingDetector::class));
		$this->assertSame([], $this->built, 'Asking builds no detector');
	}

	/**
	 * @param array<string, object> $detectors
	 */
	private function dispatcher(array $detectors, ?LoggerInterface $logger = null): SignalDispatcher {
		$settings = $this->createMock(CheckSettings::class);
		$settings->method('modeState')->willReturnCallback(function (string $id): ModeState {
			$mode = $this->modes[$id] ?? Mode::Protect;
			return new ModeState($mode, $mode);
		});
		$engine = $this->createMock(ResponseEngine::class);
		$engine->method('handle')->willReturnCallback(function (DetectionDraft $draft): ?Detection {
			$this->handled[] = $draft->checkId;
			return ($this->modes[$draft->checkId] ?? Mode::Protect) === Mode::Off ? null : new Detection();
		});
		$container = $this->createMock(ContainerInterface::class);
		$container->method('get')->willReturnCallback(function (string $class) use ($detectors): object {
			$this->built[] = $class;
			return $detectors[$class] ?? throw new \LogicException($class . ' not expected');
		});
		return new SignalDispatcher($settings, $engine, $container, $logger ?? $this->createMock(LoggerInterface::class));
	}

	/**
	 * @param list<DetectionDraft> $drafts
	 */
	private function detector(array $drafts): IDetector {
		$detector = $this->createMock(IDetector::class);
		$detector->method('detect')->willReturn($drafts);
		return $detector;
	}

	private function draft(string $checkId, bool $final = false): DetectionDraft {
		return new DetectionDraft($checkId, SourceKey::fromIp('198.51.100.7'), final: $final);
	}

	private function failedLogin(): FailedLogin {
		return new FailedLogin(SourceKey::fromIp('198.51.100.7'), 'alice', 'secret', null);
	}

	private function attempt(): AttemptRecord {
		return new AttemptRecord(AttemptKind::PasswordLogin, SourceKey::fromIp('198.51.100.7'), 'aa', null, null, 'bb', ['bb'], time(), true);
	}
}
