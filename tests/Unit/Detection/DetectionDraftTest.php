<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Unit\Detection;

use OCA\IntrusionDetection\Check\Checks\CredentialStuffing\CredentialStuffing;
use OCA\IntrusionDetection\Check\Checks\UserDenied\UserDenied;
use OCA\IntrusionDetection\Check\Checks\UserDenied\UserDeniedFacts;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Explain\DateFormatter;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\Response\Handlers\FlagSourceHandler;
use OCA\IntrusionDetection\Response\ResponseContext;
use OCP\Server;
use Test\TestCase;

class DetectionDraftTest extends TestCase {
	public function testASparedSourceIsNoBanTargetButStillASource(): void {
		$draft = new DetectionDraft(checkId: 'credential_stuffing', source: SourceKey::fromIp('198.51.100.7'));
		$draft->addBanTarget(SourceKey::fromIp('198.51.100.8'));
		$draft->spareSource();
		$this->assertSame(['198.51.100.8'], array_map(static fn (SourceKey $s): string => $s->ipKey, $draft->banTargets()));
		$this->assertSame(['198.51.100.7', '198.51.100.8'], array_map(static fn (SourceKey $s): string => $s->ipKey, $draft->sources()));
	}

	public function testASparedSourceThatIsATargetItselfIsBlocked(): void {
		$draft = new DetectionDraft(checkId: 'credential_stuffing', source: SourceKey::fromIp('198.51.100.7'));
		$draft->spareSource();
		$draft->addBanTarget(SourceKey::fromIp('198.51.100.7'));
		$this->assertCount(1, $draft->banTargets());
	}

	public function testNetworksAreBlockedOnceEach(): void {
		$draft = new DetectionDraft(checkId: 'credential_stuffing');
		$draft->addNetworkBanTarget(SourceKey::fromIp('198.51.100.7'));
		$draft->addNetworkBanTarget(SourceKey::fromIp('198.51.100.9'));
		$draft->addNetworkBanTarget(SourceKey::fromIp('203.0.113.1'));
		$this->assertSame(['198.51.100.0/24', '203.0.113.0/24'], array_map(static fn (SourceKey $s): string => $s->netKey, $draft->networkBanTargets()));
	}

	public function testFlaggingCoversASparedSourceAndTheBlockedNetworks(): void {
		$draft = new DetectionDraft(checkId: CredentialStuffing::ID, source: SourceKey::fromIp('198.51.100.7'));
		$draft->spareSource();
		$draft->addNetworkBanTarget(SourceKey::fromIp('198.51.100.7'));
		$flags = $this->createMock(FlaggedSources::class);
		$flags->expects($this->once())->method('flagSource')->with(SourceKey::fromIp('198.51.100.7'))->willReturn(time() + 60);
		$flags->expects($this->once())->method('flagNetwork')->with(SourceKey::fromIp('198.51.100.7'));
		$detection = new Detection();
		$detection->setId(3);
		$context = new ResponseContext($draft, $detection, (new CredentialStuffing($this->createMock(DateFormatter::class)))->definition(), true);
		$this->assertTrue((new FlagSourceHandler($flags))->apply($context)->enforced);
	}

	public function testAnswersAboutOneDetectionShareTheirMergeKey(): void {
		$about = static fn (string $uid, ?int $detection): ?string => (new DetectionDraft(checkId: UserDenied::ID, uid: $uid, facts: $detection === null ? null : new UserDeniedFacts(detection: $detection), merge: DetectionDraft::MERGE_SUBJECT))->mergeKey(Server::get(Fingerprinter::class));
		$this->assertNotNull($about('alice', 7));
		$this->assertSame($about('alice', 7), $about('alice', 7));
		$this->assertNotSame($about('alice', 7), $about('alice', 8));
		$this->assertNotSame($about('alice', 7), $about('bob', 7));
		$this->assertNull($about('alice', null), 'Without a detection there is nothing to merge on');
	}
}
