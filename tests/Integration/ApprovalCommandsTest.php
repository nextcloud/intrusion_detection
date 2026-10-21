<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AdminChange\ApprovalService;
use OCA\IntrusionDetection\Command\Approvals\Decide;
use OCA\IntrusionDetection\Command\Approvals\ListApprovals;
use OCA\IntrusionDetection\Db\Approval;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;

/**
 * occ intrusion:approvals:*: occ counts as the second administrator only
 * when it names one with --as, under the same rules as the admin page.
 */
#[Group('DB')]
class ApprovalCommandsTest extends AdminChangeTestCase {
	private int $id;

	protected function setUp(): void {
		parent::setUp();
		$this->requireApproval();
		$this->act($this->alice);
		$this->addAsWeb('admin', $this->bob);
		[$approval] = Server::get(ApprovalService::class)->list(true);
		$this->id = (int)$approval->getId();
	}

	public function testTheListShowsPendingRequests(): void {
		[$code, $output] = $this->runCommand(ListApprovals::class, []);
		$this->assertSame(Command::SUCCESS, $code);
		$this->assertStringContainsString($this->bob, $output);
		$this->assertStringContainsString($this->alice, $output);
		[, $json] = $this->runCommand(ListApprovals::class, ['--output' => 'json']);
		$this->assertSame($this->bob, json_decode($json, true)[0]['subject']);
	}

	public function testApprovingNeedsAnotherAdministratorNamedWithAs(): void {
		$this->assertSame(Command::INVALID, $this->runCommand(Decide::class, ['id' => (string)$this->id, '--approve' => true])[0]);
		[$code, $output] = $this->runCommand(Decide::class, ['id' => (string)$this->id, '--approve' => true, '--as' => $this->alice]);
		$this->assertSame(Command::FAILURE, $code);
		$this->assertStringContainsString('cannot approve their own request', $output);
		$this->assertSame(Command::FAILURE, $this->runCommand(Decide::class, ['id' => (string)$this->id, '--approve' => true, '--as' => $this->dave])[0]);
		$this->assertFalse($this->inGroup('admin', $this->bob));

		[$code, $output] = $this->runCommand(Decide::class, ['id' => (string)$this->id, '--approve' => true, '--as' => $this->carol]);
		$this->assertSame(Command::SUCCESS, $code, $output);
		$this->assertTrue($this->inGroup('admin', $this->bob));
		$this->assertSame($this->carol, Server::get(ApprovalService::class)->find($this->id)->getDecidedBy());
	}

	public function testRejectingWorksWithoutAs(): void {
		[$code] = $this->runCommand(Decide::class, ['id' => (string)$this->id, '--reject' => true]);
		$this->assertSame(Command::SUCCESS, $code);
		$approval = Server::get(ApprovalService::class)->find($this->id);
		$this->assertSame(Approval::STATUS_REJECTED, $approval->getStatus());
		$this->assertSame('occ', $approval->getDecidedBy());
	}

	public function testInvalidInput(): void {
		$this->assertSame(Command::INVALID, $this->runCommand(Decide::class, ['id' => (string)$this->id])[0]);
		$this->assertSame(Command::INVALID, $this->runCommand(Decide::class, ['id' => (string)$this->id, '--approve' => true, '--reject' => true])[0]);
		$this->assertSame(Command::INVALID, $this->runCommand(Decide::class, ['id' => 'x', '--reject' => true])[0]);
		$this->assertSame(Command::FAILURE, $this->runCommand(Decide::class, ['id' => '999999999', '--reject' => true])[0]);
	}

	/**
	 * @param array<string, mixed> $input
	 * @return array{int, string}
	 */
	private function runCommand(string $class, array $input): array {
		$output = new BufferedOutput();
		$code = Server::get($class)->run(new ArrayInput($input), $output);
		return [$code, $output->fetch()];
	}
}
