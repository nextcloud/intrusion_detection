<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Blocklist\Db\BlocklistRangeMapper;
use OCP\IDBConnection;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * A list version is written with multi-row inserts, not one statement per range.
 */
#[Group('DB')]
class BlocklistRangeMapperTest extends IntegrationTestCase {
	public function testManyRangesAreWrittenWithFewStatements(): void {
		$ranges = [];
		for ($i = 0; $i < 12000; $i++) {
			$start = sprintf('%032x', $i * 16);
			$ranges[] = '4' . $start . sprintf('%032x', $i * 16 + 7);
		}
		$mapper = Server::get(BlocklistRangeMapper::class);
		$queries = $this->db->getInner()->getStats()['executed'];
		$mapper->writeVersion('test_list', 3, $ranges);
		$statements = $this->db->getInner()->getStats()['executed'] - $queries;

		$perStatement = $this->db->getDatabaseProvider() === IDBConnection::PLATFORM_SQLITE ? 199 : 1000;
		$this->assertSame(1 + (int)ceil(5000 / $perStatement) * 2 + (int)ceil(2000 / $perStatement), $statements, 'one delete, then multi-row inserts per transaction of 5000');
		$this->assertSame(['start' => sprintf('%032x', 1600), 'end' => sprintf('%032x', 1607)], $mapper->findContaining('test_list', 3, 4, sprintf('%032x', 1603)));
		$this->assertNull($mapper->findContaining('test_list', 3, 4, sprintf('%032x', 1608)));
		$this->assertSame(12000, $mapper->deleteVersion('test_list', 3));
	}
}
