<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit;

use OCA\IntrusionDetection\Check\Checks\ShareBruteforceDetector;
use OCA\IntrusionDetection\Db\AttemptKind;
use OCA\IntrusionDetection\Detection\AttemptRecord;
use OCA\IntrusionDetection\Net\SourceKey;
use Test\TestCase;

/**
 * An exception logged anywhere below a detector carries the arguments of
 * every frame above it. An attempt record holds fingerprints of passwords,
 * share tokens and reset inputs, so every parameter that takes one is marked
 * sensitive, and the log shows a placeholder instead.
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
		$this->assertGreaterThanOrEqual(8, $checked);
	}

	public function testTheTraceOfAnExceptionHidesTheRecord(): void {
		$previous = ini_set('zend.exception_ignore_args', '0');
		$record = new AttemptRecord(AttemptKind::UnknownShareToken, SourceKey::fromIp('198.51.100.7'), 'secret-fingerprint-0123', null, null, null, [], time(), true);
		$detector = $this->getMockBuilder(ShareBruteforceDetector::class)->disableOriginalConstructor()->onlyMethods([])->getMock();
		try {
			$detector->unknownToken($record, null);
			$this->fail('The detector without its dependencies throws');
		} catch (\Error $e) {
			$frame = $e->getTrace()[0];
			$this->assertSame('unknownToken', $frame['function']);
			$this->assertInstanceOf(\SensitiveParameterValue::class, $frame['args'][0] ?? null);
		} finally {
			ini_set('zend.exception_ignore_args', (string)$previous);
		}
	}
}
