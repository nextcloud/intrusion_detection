<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\DecoyCredential\DecoyCredential;
use OCA\IntrusionDetection\Check\Checks\DecoyCredential\DecoyCredentialFacts;
use OCA\IntrusionDetection\Check\Checks\DecoyCredential\DecoyCredentialMatch;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Decoy\Db\DecoyMapper;
use OCA\IntrusionDetection\Decoy\DecoyFormat;
use OCA\IntrusionDetection\Decoy\DecoyService;
use OCA\IntrusionDetection\Definition\InvalidParamException;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\State\HotState;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

#[Group('DB')]
class DecoyCredentialTest extends LoginFailureTestCase {
	private DecoyService $decoys;
	private BanMapper $bans;

	protected function setUp(): void {
		parent::setUp();
		$this->decoys = Server::get(DecoyService::class);
		$this->bans = Server::get(BanMapper::class);
	}

	public function testBothFormatsLookLikeTheRealThingAndOnlyAFingerprintIsStored(): void {
		[$appPassword, $appSecret] = $this->decoys->create('old backup script on nas01', null, DecoyFormat::AppPassword, 'admin');
		[$token, $tokenSecret] = $this->decoys->create('wiki page about backups', 'backup-svc', DecoyFormat::Token, 'admin');
		$this->assertMatchesRegularExpression('/^[abcdefgijkmnopqrstwxyzABCDEFGHJKLMNPQRSTWXYZ23456789]{5}(-[abcdefgijkmnopqrstwxyzABCDEFGHJKLMNPQRSTWXYZ23456789]{5}){4}$/', $appSecret);
		$this->assertMatchesRegularExpression('/^[A-Za-z0-9]{72}$/', $tokenSecret);

		$fingerprinter = Server::get(Fingerprinter::class);
		$this->assertSame(bin2hex($fingerprinter->decoy($appSecret)), $appPassword->getSecretHmac());
		$this->assertSame(64, strlen($token->getSecretHmac()));
		$this->assertSame('backup-svc', $token->getLoginName());
		$this->assertArrayNotHasKey('secretHmac', $token->jsonSerialize());
		foreach ($this->allRows('ids_decoys') as $row) {
			$this->assertNotContains($appSecret, $row);
			$this->assertNotContains($tokenSecret, $row);
		}
		$this->assertSame(2, Server::get(HotState::class)->decoyCount());

		$this->decoys->delete($appPassword->getId(), 'admin');
		$this->assertSame(1, Server::get(HotState::class)->decoyCount());
		$this->assertCount(1, $this->decoys->list());
	}

	public function testADecoyCannotUseAnExistingAccountName(): void {
		$this->user('svc-backup');
		$this->expectException(InvalidParamException::class);
		$this->decoys->create('label', 'SVC-Backup', DecoyFormat::AppPassword, 'admin');
	}

	public function testALabelIsRequiredAndCleaned(): void {
		[$decoy] = $this->decoys->create("  note\nin drive  ", null, DecoyFormat::Token, 'admin');
		$this->assertSame('note in drive', $decoy->getLabel());
		$this->expectException(InvalidParamException::class);
		$this->decoys->create("\n ", null, DecoyFormat::Token, 'admin');
	}

	public function testUsingTheSecretBlocksForSevenDaysAtOnceWhateverTheName(): void {
		[$decoy, $secret] = $this->decoys->create('old backup script on nas01', null, DecoyFormat::AppPassword, 'admin');
		$this->failLogin('198.51.100.7', 'anything-at-all', $secret);

		$detections = $this->detectionsOf(DecoyCredential::ID);
		$this->assertCount(1, $detections);
		$this->assertSame('critical', $detections[0]->getSeverity());
		$this->assertTrue($detections[0]->isEnforced());
		$this->assertSame('old backup script on nas01', DecoyCredentialFacts::fromArray($detections[0]->getExplanationData()['facts'])->label);

		$ban = $this->bans->findActiveForKeys(['198.51.100.7'], time())[0];
		$this->assertSame(3, $ban->getLevel());
		$this->assertEqualsWithDelta(time() + 604800, $ban->getExpiresAt(), 5);
		$actions = array_column($detections[0]->getActionList(), null, 'type');
		$this->assertTrue($actions['notify_admin']['enforced']);
		$this->assertTrue($actions['ban']['ref']['bans'][0]['forced'], 'Seven days because of the decoy, not because the address came back');

		$stored = Server::get(DecoyMapper::class)->findById($decoy->getId());
		$this->assertSame(1, $stored->getTriggerCount());
		$this->assertNotNull($stored->getLastTriggeredAt());
		$this->assertSame(0, $this->rows('ids_attempts'), 'A decoy use is answered on its own');

		$narrative = Server::get(NarrativeBuilder::class)->build($detections[0], Server::get(IFactory::class)->get(Application::APP_ID, 'en'));
		$this->assertStringContainsString('used the decoy credential "old backup script on nas01"', $narrative->happened[0]);
	}

	public function testATokenDecoyIsFoundToo(): void {
		[, $secret] = $this->decoys->create('token in a shared drive', null, DecoyFormat::Token, 'admin');
		$this->failLogin('198.51.100.8', 'admin', $secret);
		$this->assertCount(1, $this->detectionsOf(DecoyCredential::ID));
	}

	public function testDecoysActDuringLearningMode(): void {
		[, $secret] = $this->decoys->create('label', null, DecoyFormat::AppPassword, 'admin');
		$this->appConfig->setValueInt(Application::APP_ID, GlobalSettings::LEARNING_UNTIL, time() + 86400);
		$this->failLogin('198.51.100.7', 'x', $secret);
		$this->assertTrue($this->detectionsOf(DecoyCredential::ID)[0]->isEnforced());
		$this->assertCount(1, $this->bans->findActiveForKeys(['198.51.100.7'], time()));
	}

	public function testTheDecoysLoginNameIsAWeakerHit(): void {
		$this->decoys->create('label', 'backup-svc', DecoyFormat::AppPassword, 'admin');
		$this->failLogin('198.51.100.7', 'Backup-Svc', 'some other password');
		$detection = $this->detectionsOf(DecoyCredential::ID)[0];
		$this->assertSame('high', $detection->getSeverity());
		$this->assertSame(DecoyCredentialMatch::LoginName, DecoyCredentialFacts::fromArray($detection->getExplanationData()['facts'])->match);
		$this->assertSame(1, $this->bans->findActiveForKeys(['198.51.100.7'], time())[0]->getLevel(), 'The usual escalation');
		$this->assertFalse(array_column($detection->getActionList(), null, 'type')['ban']['ref']['bans'][0]['forced']);
	}

	public function testTheSecretAfterTheNameRaisesTheSameDetection(): void {
		[, $secret] = $this->decoys->create('label', 'backup-svc', DecoyFormat::AppPassword, 'admin');
		$this->failLogin('198.51.100.7', 'backup-svc', 'guess');
		$this->failLogin('198.51.100.7', 'backup-svc', $secret);
		$detections = $this->detectionsOf(DecoyCredential::ID);
		$this->assertCount(1, $detections);
		$this->assertSame('critical', $detections[0]->getSeverity());
		$this->assertSame(3, $this->bans->findActiveForKeys(['198.51.100.7'], time())[0]->getLevel());
	}

	public function testALoginNameThatBecameAnAccountIsSkipped(): void {
		[, $secret] = $this->decoys->create('label', 'svc-later', DecoyFormat::AppPassword, 'admin');
		$this->user('svc-later');
		$this->assertSame(['svc-later'], $this->decoys->loginNameCollisions());
		$this->failLogin('198.51.100.7', 'svc-later', 'wrong');
		$this->assertSame([], $this->detectionsOf(DecoyCredential::ID));
		$this->failLogin('198.51.100.8', 'svc-later', $secret);
		$this->assertCount(1, $this->detectionsOf(DecoyCredential::ID), 'The secret still counts');
	}

	public function testOffSkipsTheCheck(): void {
		[, $secret] = $this->decoys->create('label', null, DecoyFormat::AppPassword, 'admin');
		$this->settingsEditor()->setMode(DecoyCredential::ID, Mode::Off);
		$this->failLogin('198.51.100.7', 'x', $secret);
		$this->assertSame([], $this->detectionsOf(DecoyCredential::ID));
	}

	public function testWithoutDecoysNothingIsLookedUp(): void {
		$this->assertNull($this->decoys->match('anything', 'anyone'));
	}
}
