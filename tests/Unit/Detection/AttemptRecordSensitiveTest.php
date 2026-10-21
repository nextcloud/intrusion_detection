<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Detection;

use OCA\IntrusionDetection\Detection\AttemptRecord;
use Test\TestCase;

/**
 * An attempt record carries password and name fingerprints in public
 * properties. Core writes the arguments of every stack frame into the log
 * when an exception is logged (for example a failed email to the admins),
 * so every parameter that takes one must be marked sensitive.
 */
class AttemptRecordSensitiveTest extends TestCase {
	public function testEveryParameterTakingAnAttemptRecordIsSensitive(): void {
		$classes = array_keys(require __DIR__ . '/../../../composer/composer/autoload_classmap.php');
		$checked = 0;
		foreach ($classes as $class) {
			if (!str_starts_with($class, 'OCA\\IntrusionDetection\\') || !class_exists($class)) {
				continue;
			}
			foreach ((new \ReflectionClass($class))->getMethods() as $method) {
				foreach ($method->getParameters() as $parameter) {
					$type = $parameter->getType();
					if ($type instanceof \ReflectionNamedType && $type->getName() === AttemptRecord::class) {
						$checked++;
						$this->assertNotSame([], $parameter->getAttributes(\SensitiveParameter::class), $class . '::' . $method->getName() . '($' . $parameter->getName() . ')');
					}
				}
			}
		}
		$this->assertGreaterThan(0, $checked);
	}
}
