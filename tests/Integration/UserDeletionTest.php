<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Privacy\UserDataCleanup;
use OCA\IntrusionDetection\Takeover\Db\SecurityChangeMapper;
use OCA\IntrusionDetection\Takeover\SecurityChangeLog;
use OCA\IntrusionDetection\Takeover\SecurityChangeType;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * What stays of a deleted account in the records of other accounts.
 */
#[Group('DB')]
class UserDeletionTest extends IntegrationTestCase {
	public function testAChangeADeletedAdministratorMadeStaysWithoutThem(): void {
		$mapper = Server::get(SecurityChangeMapper::class);
		$id = $mapper->insert([
			'uid' => 'ids-changed-user',
			'type' => SecurityChangeType::EmailChanged->value,
			'via' => SecurityChangeLog::VIA_ADMIN,
			'actor_uid' => 'ids-gone-admin',
			'old_value_hint' => null,
			'new_value_hint' => null,
			'notify_to' => null,
			'ref_id' => null,
			'detail' => null,
			'session_token_id' => null,
			'ip' => null,
			'created_at' => time(),
		]);

		Server::get(UserDataCleanup::class)->deleteUser('ids-gone-admin');

		$row = $mapper->find($id);
		$this->assertNotNull($row, 'The change stays in the history of the account it was made to');
		$this->assertNull($row['actor_uid']);
		$this->assertSame(SecurityChangeLog::VIA_ADMIN, $row['via']);
	}
}
