<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\Check\Checks\AccountUnderAttack;
use OCA\IntrusionDetection\Check\Checks\CredentialStuffing;
use OCA\IntrusionDetection\Check\Checks\PasswordSpraying;
use OCA\IntrusionDetection\Check\Mode;
use OCA\IntrusionDetection\Check\ResponseType;
use OCA\IntrusionDetection\Db\BanMapper;
use OCA\IntrusionDetection\Db\ProtectedAccountMapper;
use OCA\IntrusionDetection\Explain\IExplainsToUser;
use OCA\IntrusionDetection\Notification\UserAlerts;
use OCA\IntrusionDetection\Response\AccountProtection;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\ICacheFactory;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

#[Group('DB')]
class AccountUnderAttackTest extends LoginFailureTestCase {
	private ProtectedAccountMapper $protected;
	private string $uid;

	protected function setUp(): void {
		parent::setUp();
		$this->protected = Server::get(ProtectedAccountMapper::class);
		$this->settings->setMode(CredentialStuffing::ID, Mode::Off);
		$this->settings->setMode(PasswordSpraying::ID, Mode::Off);
		// A fresh account per test: the protection is cached per account for a minute.
		$this->uid = 'ids-aua-' . bin2hex(random_bytes(4));
		$this->user($this->uid);
	}

	public function testManyAddressesGuessingOneAccountProtectItForADay(): void {
		$this->attack(9, 5);
		$this->assertSame([], $this->detectionsOf(AccountUnderAttack::ID), '9 failures are below the limit of 10');

		$this->failLogin('198.51.100.10', $this->uid);
		$detections = $this->detectionsOf(AccountUnderAttack::ID);
		$this->assertCount(1, $detections);
		$this->assertSame($this->uid, $detections[0]->getUid());
		$this->assertNull($detections[0]->getIp(), 'The detection is about the account, not one address');

		$row = $this->protected->find($this->uid);
		$this->assertNotNull($row);
		$this->assertEqualsWithDelta(time() + 86400, $row['expires_at'], 5);
		$this->assertSame($detections[0]->getId(), $row['detection_id']);
		$this->assertTrue($this->freshProtection()->isProtected($this->uid));

		$actions = array_column($detections[0]->getActionList(), null, 'type');
		$this->assertTrue($actions['protect_account']['enforced']);
		$this->assertTrue($actions['notify_user']['enforced'], 'The user is told');
		$this->assertSame(UserAlerts::EMAIL_NO_ADDRESS, $actions['notify_user']['ref']['email'] ?? null);
		$this->assertSame(0, $actions['notify_user']['ref']['admins'] ?? null, 'Medium severity: the admins are not asked to reach out');
		$this->assertSame(0, $this->rows('ids_bans'), 'Blocking is off by default');
	}

	public function testTooFewAddressesDoNotFire(): void {
		$this->attack(12, 4);
		$this->assertSame([], $this->detectionsOf(AccountUnderAttack::ID));
		$this->assertNull($this->protected->find($this->uid));
	}

	public function testUnknownLoginNamesAreNotAccounts(): void {
		for ($i = 1; $i <= 12; $i++) {
			$this->failLogin('198.51.100.' . $i, 'nobody-' . $this->uid);
		}
		$this->assertSame([], $this->detectionsOf(AccountUnderAttack::ID));
		foreach ($this->allRows('ids_attempts') as $row) {
			$this->assertNull($row['uid']);
		}
	}

	public function testAnEmailAddressOfExactlyOneAccountResolvesToIt(): void {
		$this->user($this->uid)->setSystemEMailAddress($this->uid . '@example.com');
		$this->failLogin('198.51.100.1', $this->uid . '@example.com');
		$this->assertSame($this->uid, $this->allRows('ids_attempts')[0]['uid']);
	}

	public function testASingleFailureBelowTheLimitsNeverExtendsTheProtection(): void {
		$protection = $this->freshProtection();
		$protection->protect($this->uid, time() + 600);
		$this->failLogin('198.51.100.1', $this->uid);
		$this->assertEqualsWithDelta(time() + 600, $this->protected->find($this->uid)['expires_at'], 5, 'An occasional guess cannot keep the account protected');
	}

	public function testTheProtectionIsExtendedWhileTheLimitsAreReached(): void {
		$this->attack(10, 5);
		$this->freshProtection()->protect($this->uid, time() + 600);
		$this->failLogin('198.51.100.11', $this->uid);
		$this->assertEqualsWithDelta(time() + 86400, $this->protected->find($this->uid)['expires_at'], 5);
	}

	public function testAnUnprotectedAccountIsNotProtectedByASingleFailure(): void {
		$this->failLogin('198.51.100.1', $this->uid);
		$this->assertNull($this->protected->find($this->uid));
	}

	public function testBlockingAddressesIsOptionalAndNeedsRepeatedFailures(): void {
		$this->settings->setResponses(AccountUnderAttack::ID, [ResponseType::ProtectAccount, ResponseType::Ban]);
		// Five addresses guess four passwords each, four more fail once.
		for ($i = 1; $i <= 5; $i++) {
			for ($guess = 1; $guess <= 4; $guess++) {
				$this->storeAttempt('203.0.113.' . $i, $this->uid, $this->uid, 'guess-' . $guess);
			}
		}
		for ($i = 6; $i <= 9; $i++) {
			$this->storeAttempt('203.0.113.' . $i, $this->uid, $this->uid, 'guess-1');
		}
		// A device with an old saved password, and a person who mistypes three times.
		for ($retry = 1; $retry <= 8; $retry++) {
			$this->storeAttempt('203.0.113.20', $this->uid, $this->uid, 'the-old-password');
		}
		foreach (['typo-1', 'typo-2', 'typo-3'] as $typo) {
			$this->storeAttempt('203.0.113.21', $this->uid, $this->uid, $typo);
		}
		$this->failLogin('203.0.113.10', $this->uid);
		$bans = Server::get(BanMapper::class);
		$this->assertCount(1, $bans->findActiveForKeys(['203.0.113.3'], time()));
		$this->assertSame([], $bans->findActiveForKeys(['203.0.113.7'], time()));
		$this->assertSame([], $bans->findActiveForKeys(['203.0.113.10'], time()));
		$this->assertSame([], $bans->findActiveForKeys(['203.0.113.20'], time()), 'One password over and over is a device, not a guesser');
		$this->assertSame([], $bans->findActiveForKeys(['203.0.113.21'], time()));
	}

	public function testObserveProtectsNothing(): void {
		$this->settings->setMode(AccountUnderAttack::ID, Mode::Observe);
		$this->attack(10, 5);
		$this->assertFalse($this->detectionsOf(AccountUnderAttack::ID)[0]->isEnforced());
		$this->assertNull($this->protected->find($this->uid));
	}

	public function testAnAdminCanEndTheProtectionEarly(): void {
		$this->attack(10, 5);
		$protection = $this->freshProtection();
		$this->assertTrue($protection->end($this->uid, 'admin'));
		$this->assertFalse($protection->isProtected($this->uid));
		$this->assertFalse($protection->end($this->uid, 'admin'), 'Ending twice changes nothing');
	}

	public function testTheUserNoticeNamesTheEndOfTheProtection(): void {
		$this->attack(10, 5);
		$detection = $this->detectionsOf(AccountUnderAttack::ID)[0];
		$check = Server::get(AccountUnderAttack::class);
		$this->assertInstanceOf(IExplainsToUser::class, $check);
		$notice = $check->userNotice($detection, Server::get(IFactory::class)->get(Application::APP_ID, 'en'));
		$this->assertSame('Someone is trying to guess your password', $notice->subject);
		$text = implode(' ', $notice->message);
		$this->assertStringContainsString('logins with your password need an extra confirmation', $text);
		$this->assertStringNotContainsString('limit', $text, 'Users never see thresholds');
		$this->assertStringNotContainsString('198.51.100', $text, 'nor the attacking addresses');
	}

	private function attack(int $failures, int $sources): void {
		for ($i = 1; $i <= $failures; $i++) {
			$this->failLogin('198.51.100.' . ($i % $sources + 1), $this->uid);
		}
	}

	private function freshProtection(): AccountProtection {
		return new AccountProtection($this->protected, Server::get(ITimeFactory::class), Server::get(ICacheFactory::class), Server::get(AuditLogger::class));
	}
}
