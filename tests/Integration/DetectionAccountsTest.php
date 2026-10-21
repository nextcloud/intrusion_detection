<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Check\Checks\AdminChange;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffing;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Db\DetectionAccountMapper;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Detection\DetectionAccounts;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Detection\DetectionService;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Privacy\UserDataCleanup;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * The accounts each detection names are kept in a side table, so that
 * deleting an account and its incident report use an index.
 */
#[Group('DB')]
class DetectionAccountsTest extends IntegrationTestCase {
	private DetectionService $service;
	private DetectionAccountMapper $accounts;
	private ModeState $protect;

	protected function setUp(): void {
		parent::setUp();
		$this->service = Server::get(DetectionService::class);
		$this->accounts = Server::get(DetectionAccountMapper::class);
		$this->protect = new ModeState(Mode::Protect, Mode::Protect);
	}

	public function testTheAccountsOfADetectionComeFromItsAccountFactsAndActions(): void {
		$detection = new Detection();
		$detection->setUid('alice');
		$detection->setExplanationData(['facts' => ['targets' => ['bob', 'alice', ''], 'actor' => 'admin', 'users' => ['carol'], 'name' => 'not-an-account-key']]);
		$detection->setActionList([['type' => 'protect_account', 'enforced' => true, 'ref' => ['uid' => 'dave', 'until' => 5]], ['type' => 'ban', 'enforced' => true, 'ref' => 'ref-1']]);
		$this->assertSame(['alice', 'bob', 'carol', 'admin', 'dave'], DetectionAccounts::of($detection));
	}

	public function testRecordingMergingAndActionsAddTheirAccounts(): void {
		$draft = fn (array $targets): DetectionDraft => new DetectionDraft(CredentialStuffing::ID, SourceKey::fromIp('203.0.113.5'), null, ['targets' => $targets], merge: DetectionDraft::MERGE_SOURCE);
		[$detection] = $this->service->record($draft(['alice', 'bob']), $this->protect);
		$this->assertEqualsCanonicalizing(['alice', 'bob'], $this->accounts->uids($detection->getId()));

		$queries = $this->queries();
		[$merged, $new] = $this->service->record($draft(['alice']), $this->protect);
		$this->assertFalse($new);
		$this->assertSame(2, $this->queries() - $queries, 'a merge that names no new account writes no account row');

		$this->service->record($draft(['carol']), $this->protect);
		$this->service->setActions($merged, [['type' => ResponseType::ProtectAccount->value, 'enforced' => true, 'ref' => ['uid' => 'dave']]]);
		$this->assertEqualsCanonicalizing(['alice', 'bob', 'carol', 'dave'], $this->accounts->uids($detection->getId()));
	}

	public function testDeletingAnAccountReadsOnlyItsDetections(): void {
		for ($i = 0; $i < 50; $i++) {
			$this->service->record(new DetectionDraft(CredentialStuffing::ID, SourceKey::fromIp('198.51.100.' . $i), null, ['targets' => ['bob'], 'note' => 'alice is only a word here']), $this->protect);
		}
		[$attack] = $this->service->record(new DetectionDraft(CredentialStuffing::ID, SourceKey::fromIp('203.0.113.9'), null, ['targets' => ['alice', 'bob']]), $this->protect);
		[$change] = $this->service->record(new DetectionDraft(AdminChange::ID, null, 'bob', ['actor' => 'alice', 'kind' => 'admin_granted']), $this->protect);

		$queries = $this->queries();
		Server::get(UserDataCleanup::class)->deleteUser('alice');
		$this->assertLessThan(30, $this->queries() - $queries, 'two detections rewritten, not fifty read');

		$mapper = Server::get(DetectionMapper::class);
		$this->assertSame(['bob'], $mapper->findById($attack->getId())->getExplanationData()['facts']['targets']);
		$this->assertNull($mapper->findById($change->getId())->getExplanationData()['facts']['actor']);
		$this->assertSame([], $this->accounts->detectionIds('alice', 0, 100));
		$this->assertCount(52, $this->accounts->detectionIds('bob', 0, 100));
	}

	public function testRetentionDeletesTheAccountsWithTheirDetections(): void {
		[$old] = $this->service->record(new DetectionDraft(CredentialStuffing::ID, SourceKey::fromIp('203.0.113.10'), null, ['targets' => ['alice']]), $this->protect);
		$mapper = Server::get(DetectionMapper::class);
		$old->setCreatedAt(1000);
		$mapper->update($old);
		[$kept] = $this->service->record(new DetectionDraft(CredentialStuffing::ID, SourceKey::fromIp('203.0.113.11'), null, ['targets' => ['alice']]), $this->protect);

		$this->assertSame(1, $mapper->deleteCreatedBefore(2000));
		$this->assertSame([$kept->getId()], $this->accounts->detectionIds('alice', 0, 10));
	}

	public function testTheBackfillRecordsStoredDetectionsOnce(): void {
		[$detection] = $this->service->record(new DetectionDraft(CredentialStuffing::ID, SourceKey::fromIp('203.0.113.12'), 'carol', ['targets' => ['alice']]), $this->protect);
		$this->accounts->deleteForDetections([$detection->getId()]);

		Server::get(DetectionAccounts::class)->backfill();
		Server::get(DetectionAccounts::class)->backfill();
		$this->assertEqualsCanonicalizing(['alice', 'carol'], $this->accounts->uids($detection->getId()));
	}

	private function queries(): int {
		return $this->db->getInner()->getStats()['executed'];
	}
}
