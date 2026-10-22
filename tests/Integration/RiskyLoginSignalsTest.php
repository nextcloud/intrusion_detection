<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Check\Checks\RiskyNetwork\RiskyNetwork;
use OCA\IntrusionDetection\Config\ModeState;
use OCA\IntrusionDetection\Confirm\LoginDetections;
use OCA\IntrusionDetection\Db\DetectionMapper;
use OCA\IntrusionDetection\Db\LoginHistoryMapper;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Detection\DetectionDraft;
use OCA\IntrusionDetection\Detection\DetectionService;
use OCA\IntrusionDetection\LoginHistory\LoginHistory;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Risk\RiskAssessment;
use OCA\IntrusionDetection\Risk\RiskScorer;
use OCA\IntrusionDetection\Takeover\RiskyLogin;
use OCA\IntrusionDetection\Takeover\Signals\RiskyNetworkSignal;
use OCA\IntrusionDetection\Takeover\Signals\UnknownDeviceSignal;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;

/**
 * The risky-login evidence that the login history and the risky network
 * check give the takeover check (concept section 10.14).
 */
#[Group('DB')]
class RiskyLoginSignalsTest extends IntegrationTestCase {
	private LoginHistoryMapper $history;

	protected function setUp(): void {
		parent::setUp();
		$this->history = Server::get(LoginHistoryMapper::class);
	}

	private function login(int $at, string $method, bool $knownDevice, int $token, string $ip = '198.51.100.7'): void {
		$this->history->insert('alice', $at, SourceKey::fromIp($ip), null, $method, $knownDevice, LoginHistory::CONFIRMED_BY_NONE, null, $token);
	}

	private function unknownDevice(int $score, bool $enabled = true): UnknownDeviceSignal {
		$scorer = $this->createMock(RiskScorer::class);
		$scorer->method('isEnabled')->willReturn($enabled);
		$scorer->method('score')->willReturn(new RiskAssessment($score, RiskAssessment::TIER_NORMAL, 1.0, [], 2, 4));
		return new UnknownDeviceSignal($this->history, $scorer);
	}

	public function testAPasswordLoginFromAnUnknownDeviceOnARaisedScoreIsRisky(): void {
		$at = time() - 600;
		$this->login($at, LoginHistory::METHOD_PASSWORD, false, 41);
		$login = $this->unknownDevice(2)->riskyLogin('alice', 41);
		$this->assertSame($at, $login?->at);
		$this->assertSame(RiskyLogin::REASON_UNKNOWN_DEVICE, $login?->reason);

		$this->assertNull($this->unknownDevice(1)->riskyLogin('alice', 41), 'Below the elevated tier');
		$this->assertNull($this->unknownDevice(5, enabled: false)->riskyLogin('alice', 41), 'The score is switched off');
		$this->assertNull($this->unknownDevice(5)->riskyLogin('bob', 41), 'Another account\'s session');
		$this->assertNull($this->unknownDevice(5)->riskyLogin('alice', null));
	}

	public function testARememberedDeviceOrATokenLoginIsNotAnUnknownDevice(): void {
		$this->login(time(), LoginHistory::METHOD_PASSWORD, true, 42);
		$this->login(time(), LoginHistory::METHOD_APP_PASSWORD, false, 43);
		$this->assertNull($this->unknownDevice(5)->riskyLogin('alice', 42));
		$this->assertNull($this->unknownDevice(5)->riskyLogin('alice', 43));
	}

	public function testASessionLinkedToARiskyNetworkDetectionIsRisky(): void {
		$at = time() - 900;
		$this->login($at, LoginHistory::METHOD_PASSWORD, false, 51);
		$service = Server::get(DetectionService::class);
		$protect = new ModeState(Mode::Protect, Mode::Protect);
		$service->record(new DetectionDraft(RiskyNetwork::ID, SourceKey::fromIp('198.51.100.7'), 'alice', [LoginDetections::FACT => [50, 51]]), $protect);
		$signal = new RiskyNetworkSignal(Server::get(DetectionMapper::class), $this->history, Server::get(ITimeFactory::class));

		$login = $signal->riskyLogin('alice', 51);
		$this->assertSame($at, $login?->at, 'From the login history');
		$this->assertSame(RiskyLogin::REASON_RISKY_NETWORK, $login?->reason);
		$this->assertNotNull($signal->riskyLogin('alice', 50), 'Without a history row, the detection\'s time');
		$this->assertNull($signal->riskyLogin('alice', 52), 'Another session');
		$this->assertNull($signal->riskyLogin('bob', 51));
	}
}
