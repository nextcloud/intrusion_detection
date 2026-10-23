<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Perf\FreshRequestProbe;
use PHPUnit\Framework\Attributes\Group;

/**
 * What a plain request costs in a new PHP process (concept section 19): the
 * first settings read makes core load the config lexicon, which must not
 * build checks or setting definitions, and the guards must stay light.
 */
#[Group('DB')]
class FreshRequestBenchmarkTest extends IntegrationTestCase {
	/** Classes of the app a plain request loads at most, guards and settings together */
	private const MAX_APP_CLASSES = 45;
	/** A generous bound for slow test machines; a new process measured about 1 ms without opcache */
	private const SETTINGS_BUDGET_US = 25000;

	public function testAPlainRequestLoadsNoCheckAndFewClasses(): void {
		$result = FreshRequestProbe::inNewProcess();
		$this->assertSame(\OC::$SERVERROOT, FreshRequestProbe::serverRoot());
		$this->assertNotNull($result, 'the probe ran in a new PHP process');

		// The guards' own classes live in their check's folder; the check and its detector must not load.
		$checks = array_values(array_filter($result['classes'], static fn (string $class): bool => preg_match('/^OCA\\\\IntrusionDetection\\\\Check\\\\Checks\\\\(\\w+)\\\\\\1(Detector)?$/', $class) === 1
			|| str_starts_with($class, 'OCA\\IntrusionDetection\\Confirm\\')
			|| str_starts_with($class, 'OCA\\IntrusionDetection\\Explain\\')));
		$this->assertSame([], $checks, 'no check, step-up reason or explanation class is loaded');
		$this->assertNotContains('OCA\\IntrusionDetection\\Definition\\CheckDefinition', $result['classes']);
		$this->assertContains('OCA\\IntrusionDetection\\Config\\LexiconData', $result['classes']);
		$this->assertLessThanOrEqual(self::MAX_APP_CLASSES, $result['app_classes'], implode(', ', $result['classes']));
		$this->assertLessThan(self::SETTINGS_BUDGET_US, $result['settings_us']);
		$this->assertLessThanOrEqual(2, $result['queries'], 'a cold address verdict is one query per enabled source');
	}
}
