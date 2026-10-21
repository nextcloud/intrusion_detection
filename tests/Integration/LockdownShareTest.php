<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\Files_Sharing\Controller\ShareController;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\ShareBruteforce;
use OCA\IntrusionDetection\Check\Checks\ShareBruteforceDetector;
use OCA\IntrusionDetection\Detection\AttemptRecorder;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Listener\ShareAccessFailedListener;
use OCA\IntrusionDetection\Lockdown\LockdownService;
use OCA\IntrusionDetection\Risk\RiskLimits;
use OCP\L10N\IFactory;
use OCP\Server;
use OCP\Share\Events\ShareLinkAccessFailedEvent;
use OCP\Share\IShare;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;

/**
 * During lockdown, the password of a share link may be guessed wrong only
 * 3 times from one address instead of 5 (concept section 11.14), through
 * the share page of core's sharing app.
 */
#[Group('DB')]
class LockdownShareTest extends RequestEventTestCase {
	private const SHARE_PASSWORD = 'Correct-Horse-Battery-Staple-1';

	protected function setUp(): void {
		parent::setUp();
		$this->listen(ShareLinkAccessFailedEvent::class, new ShareAccessFailedListener(
			$this->settings,
			$this->addresses,
			Server::get(AttemptRecorder::class),
			Server::get(ShareBruteforceDetector::class),
			$this->request,
			Server::get(LoggerInterface::class),
		));
	}

	public function testThreeWrongPasswordsAreEnoughDuringLockdown(): void {
		$share = $this->linkShare($this->user('ids-lockdown-share-owner'), self::SHARE_PASSWORD);
		Server::get(LockdownService::class)->start(3600, '', 'admin', ['share_password']);
		for ($i = 0; $i < 2; $i++) {
			$this->enterWrongPassword('198.51.100.7', $share);
		}
		$this->assertSame([], $this->detectionsOf(ShareBruteforce::ID));
		$this->enterWrongPassword('198.51.100.7', $share);
		$detections = $this->detectionsOf(ShareBruteforce::ID);
		$this->assertCount(1, $detections);
		$facts = $detections[0]->getExplanationData()['facts'];
		$this->assertSame(ShareBruteforce::RULE_PASSWORD_SOURCE, $facts['rule']);
		$this->assertSame(['password_min_per_source' => 3], $facts[RiskLimits::LOCKDOWN_KEY]['caps']);
		$narrative = Server::get(NarrativeBuilder::class)->build($detections[0], Server::get(IFactory::class)->get(Application::APP_ID, 'en'));
		$this->assertStringContainsString('3 instead of 5, because lockdown mode was on', implode(' ', $narrative->happened));
	}

	public function testOutsideALockdownTheUsualLimitApplies(): void {
		$share = $this->linkShare($this->user('ids-lockdown-share-owner'), self::SHARE_PASSWORD);
		for ($i = 0; $i < 3; $i++) {
			$this->enterWrongPassword('198.51.100.7', $share);
		}
		$this->assertSame([], $this->detectionsOf(ShareBruteforce::ID));
	}

	private function enterWrongPassword(string $ip, IShare $share): void {
		$this->remoteAddress = $ip;
		$controller = Server::get(ShareController::class);
		$controller->setToken($share->getToken());
		$this->assertTrue($controller->isValidToken());
		$controller->authenticate('not-the-password');
	}
}
