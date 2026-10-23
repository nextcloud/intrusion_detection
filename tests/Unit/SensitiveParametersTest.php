<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit;

use OCA\IntrusionDetection\Check\Checks\ShareBruteforce\ShareBruteforceDetector;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Detection\AttemptRecord;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Signal\ISignal;
use OCA\IntrusionDetection\Signal\ShareAccessFailed;
use Test\TestCase;

/**
 * An exception logged anywhere below a detector carries the arguments of
 * every frame above it. An attempt record holds fingerprints of passwords,
 * share tokens and reset inputs, and the fingerprinter takes the secrets
 * themselves, so every parameter that takes one is marked sensitive, and
 * the log shows a placeholder instead.
 */
class SensitiveParametersTest extends TestCase {
	public function testEveryParameterThatTakesAnAttemptRecordIsSensitive(): void {
		$classmap = require __DIR__ . '/../../composer/composer/autoload_classmap.php';
		$checked = 0;
		foreach (array_keys($classmap) as $class) {
			if (!str_starts_with($class, 'OCA\\IntrusionDetection\\') || !(class_exists($class) || interface_exists($class))) {
				continue;
			}
			foreach ((new \ReflectionClass($class))->getMethods() as $method) {
				foreach ($method->getParameters() as $parameter) {
					$type = $parameter->getType();
					if ($type instanceof \ReflectionNamedType && $type->getName() === AttemptRecord::class) {
						$checked++;
						$this->assertNotSame([], $parameter->getAttributes(\SensitiveParameter::class), $class . '::' . $method->getName() . '($' . $parameter->getName() . ') must be #[\SensitiveParameter]');
					}
				}
			}
		}
		$this->assertGreaterThanOrEqual(4, $checked);
	}

	public function testEveryParameterThatTakesASignalIsSensitive(): void {
		$checked = 0;
		foreach (self::appClasses() as $class) {
			foreach ((new \ReflectionClass($class))->getMethods() as $method) {
				foreach ($method->getParameters() as $parameter) {
					$type = $parameter->getType();
					if ($type instanceof \ReflectionNamedType && !$type->isBuiltin() && is_a($type->getName(), ISignal::class, true)) {
						$checked++;
						$this->assertNotSame([], $parameter->getAttributes(\SensitiveParameter::class), $class . '::' . $method->getName() . '($' . $parameter->getName() . ') must be #[\SensitiveParameter]');
					}
				}
			}
		}
		$this->assertGreaterThanOrEqual(8, $checked);
	}

	public function testASignalWithASecretHidesItFromDumps(): void {
		$checked = 0;
		foreach (self::appClasses() as $class) {
			$reflection = new \ReflectionClass($class);
			if (!$reflection->implementsInterface(ISignal::class) || $reflection->isInterface()) {
				continue;
			}
			$secrets = array_filter($reflection->getConstructor()?->getParameters() ?? [], static fn (\ReflectionParameter $p): bool => $p->getAttributes(\SensitiveParameter::class) !== []);
			if ($secrets === []) {
				continue;
			}
			$checked++;
			$this->assertTrue($reflection->hasMethod('__debugInfo') && $reflection->getMethod('__debugInfo')->getDeclaringClass()->getName() === $class, $class . ' carries a secret and must define __debugInfo()');
		}
		$this->assertGreaterThanOrEqual(2, $checked);
	}

	/**
	 * @return list<class-string>
	 */
	private static function appClasses(): array {
		$classmap = require __DIR__ . '/../../composer/composer/autoload_classmap.php';
		return array_values(array_filter(array_keys($classmap), static fn (string $class): bool => str_starts_with($class, 'OCA\\IntrusionDetection\\') && (class_exists($class) || interface_exists($class))));
	}

	public function testEverySecretTheFingerprinterTakesIsSensitive(): void {
		$checked = 0;
		foreach ((new \ReflectionClass(Fingerprinter::class))->getMethods() as $method) {
			if ($method->isConstructor() || in_array($method->getName(), ['today', 'key'], true)) {
				continue;
			}
			$secret = $method->getParameters()[0] ?? null;
			$this->assertNotNull($secret, $method->getName());
			$checked++;
			$this->assertNotSame([], $secret->getAttributes(\SensitiveParameter::class), 'Fingerprinter::' . $method->getName() . '($' . $secret->getName() . ') must be #[\SensitiveParameter]');
		}
		$this->assertGreaterThanOrEqual(11, $checked);
	}

	public function testTheTraceOfAnExceptionHidesTheRecord(): void {
		$previous = ini_set('zend.exception_ignore_args', '0');
		$record = new AttemptRecord(AttemptKind::UnknownShareToken, SourceKey::fromIp('198.51.100.7'), 'secret-fingerprint-0123', null, null, null, [], time(), true);
		$detector = $this->getMockBuilder(ShareBruteforceDetector::class)->disableOriginalConstructor()->onlyMethods([])->getMock();
		try {
			$detector->detect(new ShareAccessFailed($record, null, null), new ModeState(Mode::Protect, Mode::Protect));
			$this->fail('The detector without its dependencies throws');
		} catch (\Error $e) {
			$frames = array_column($e->getTrace(), null, 'function');
			foreach (['unknownToken', 'detect'] as $function) {
				$this->assertInstanceOf(\SensitiveParameterValue::class, $frames[$function]['args'][0] ?? null, $function);
			}
		} finally {
			ini_set('zend.exception_ignore_args', (string)$previous);
		}
	}
}
