<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionFilter;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * The dashboard widget asks for the detections newer than the newest one it has.
 */
#[Group('DB')]
class DetectionAfterIdTest extends IntegrationTestCase {
	public function testOnlyDetectionsAfterTheIdAreListed(): void {
		$mapper = Server::get(DetectionMapper::class);
		$ids = [];
		for ($i = 0; $i < 3; $i++) {
			$detection = new Detection();
			$detection->setCheckId('trap_url');
			$detection->setSeverity('high');
			$detection->setEnforced(true);
			$detection->setExplanationData([]);
			$detection->setActionList([]);
			$detection->setCreatedAt(time());
			$detection->setLastSeenAt(time());
			$detection->setHits(1);
			$ids[] = $mapper->insert($detection)->getId();
		}
		$found = $mapper->findList(new DetectionFilter(afterId: $ids[0]));
		$this->assertEqualsCanonicalizing([$ids[1], $ids[2]], array_map(static fn (Detection $d): int => $d->getId(), $found));
	}
}
