<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\SetupCheck;

use OCA\IntrusionDetection\AdminChange\AdminGrantGate;
use OCA\IntrusionDetection\AdminChange\Approvers;
use OCA\IntrusionDetection\SetupCheck\ApprovalCheck;
use OCP\L10N\IFactory;
use OCP\Server;
use OCP\SetupCheck\SetupResult;
use Test\TestCase;

class ApprovalCheckTest extends TestCase {
	public function testApprovalOffIsFine(): void {
		$this->assertSame(SetupResult::SUCCESS, $this->check(false, 1)->getSeverity());
	}

	public function testApprovalWithOneAdminIsAnError(): void {
		$result = $this->check(true, 1);
		$this->assertSame(SetupResult::ERROR, $result->getSeverity());
		$this->assertStringContainsString('nobody can approve', (string)$result->getDescription());
	}

	public function testApprovalWithTwoAdminsIsFine(): void {
		$this->assertSame(SetupResult::SUCCESS, $this->check(true, 2)->getSeverity());
	}

	private function check(bool $required, int $admins): SetupResult {
		$gate = $this->createMock(AdminGrantGate::class);
		$gate->method('isRequired')->willReturn($required);
		$approvers = $this->createMock(Approvers::class);
		$approvers->method('count')->willReturn($admins);
		return (new ApprovalCheck($gate, $approvers, Server::get(IFactory::class)->get('intrusion_detection', 'en')))->run();
	}
}
