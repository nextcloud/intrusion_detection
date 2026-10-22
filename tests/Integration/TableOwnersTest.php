<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\BackgroundJob\Cleanup;
use OCA\IntrusionDetection\Db\IPurges;
use OCA\IntrusionDetection\Privacy\UserDataCleanup;
use PHPUnit\Framework\Attributes\Group;

/**
 * Every table of the app, as the database schema has it, has an owner that
 * deletes its rows past their retention and an entry in the privacy
 * cleanup, or a reason why not. A new table fails here until it has both.
 */
#[Group('DB')]
class TableOwnersTest extends IntegrationTestCase {
	/** Tables the cleanup job does not purge, and why */
	private const NOT_PURGED = [
		'ids_approvals' => 'the approval expiry job ends requests and deletes decided ones (ApprovalService::expireDue)',
		'ids_blocklist_ranges' => 'the blocklist sync keeps the current and the previous version of each list',
		'ids_blocklist_stats' => 'the blocklist sync deletes the days past BlocklistSync::STATS_DAYS',
		'ids_config_snapshot' => 'one row per watched setting, replaced when the setting changes',
		'ids_decoys' => 'kept until an administrator deletes them',
		'ids_state' => 'the app\'s internal state, one row per name, kept by its owner',
	];

	/** Tables the privacy cleanup's DELETE and ANONYMISE maps leave out, and why */
	private const NOT_IN_PRIVACY_MAPS = [
		'ids_alerts' => 'the counters about the account are deleted by their source key',
		'ids_bans' => 'blocks are about addresses; who created or lifted one stays, like any decision',
		'ids_blocklist_ranges' => 'address ranges of public lists',
		'ids_blocklist_stats' => 'counts per list and day',
		'ids_config_snapshot' => 'hashes and display values of administrator settings',
		'ids_decoys' => 'made-up credentials',
		'ids_detection_accounts' => 'deleted once the detections of the account are rewritten',
		'ids_detection_hourly' => 'counts per check and hour',
		'ids_detections' => 'rewritten without the account by a queued job',
		'ids_flags' => 'flags of addresses, networks, tools and password fingerprints',
		'ids_state' => 'the app\'s internal state',
	];

	public function testEveryTableHasAPurgeOwnerOrAReason(): void {
		$owned = [];
		foreach (Cleanup::PURGES as $owner => $tables) {
			$this->assertTrue(is_subclass_of($owner, IPurges::class), $owner . ' purges');
			foreach ($tables as $table) {
				$this->assertArrayNotHasKey($table, $owned, $table . ' has one owner');
				$owned[$table] = $owner;
			}
		}
		$this->assertSame([], array_values(array_intersect(array_keys($owned), array_keys(self::NOT_PURGED))), 'a purged table needs no reason');
		$this->assertSame(self::tables(), self::sorted([...array_keys($owned), ...array_keys(self::NOT_PURGED)]));
	}

	public function testEveryTableIsInThePrivacyCleanupOrHasAReason(): void {
		$mapped = [...array_keys(UserDataCleanup::DELETE), ...array_keys(UserDataCleanup::ANONYMISE)];
		$this->assertSame([], array_values(array_intersect($mapped, array_keys(self::NOT_IN_PRIVACY_MAPS))), 'a mapped table needs no reason');
		$this->assertSame(self::tables(), self::sorted([...$mapped, ...array_keys(self::NOT_IN_PRIVACY_MAPS)]));
	}

	/**
	 * @param list<string> $tables
	 * @return list<string>
	 */
	private static function sorted(array $tables): array {
		sort($tables);
		return $tables;
	}
}
