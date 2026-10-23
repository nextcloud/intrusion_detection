<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Db\Approval;
use OCA\IntrusionDetection\Db\ApprovalMapper;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * Expired requests that the hourly job has not marked yet count as pending
 * nowhere: not for the limit of pending requests and not in the metric.
 */
#[Group('DB')]
class ApprovalCountTest extends IntegrationTestCase {
	public function testExpiredRequestsAreNotPending(): void {
		$mapper = Server::get(ApprovalMapper::class);
		$now = 1_800_000_000;
		foreach ([$now - 10, $now + 3600, $now + 7200] as $i => $expiresAt) {
			$approval = new Approval();
			$approval->setKind($i === 2 ? Approval::KIND_LOGIN : Approval::KIND_ADMIN_GRANT);
			$approval->setSubjectUid('user' . $i);
			$approval->setRequestedBy('admin');
			$approval->setStatus(Approval::STATUS_PENDING);
			$approval->setCreatedAt($now - 100);
			$approval->setExpiresAt($expiresAt);
			$mapper->insert($approval);
		}
		$this->assertSame(1, $mapper->countPending(Approval::KIND_ADMIN_GRANT, $now));
		$this->assertSame(1, $mapper->countPending(Approval::KIND_LOGIN, $now));
		$this->assertSame([Approval::KIND_ADMIN_GRANT => 1, Approval::KIND_LOGIN => 1], $mapper->countPendingByKind($now));
	}
}
