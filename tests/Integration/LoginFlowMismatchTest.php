<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OC\Authentication\Token\IProvider;
use OC\Core\Db\LoginFlowV2Mapper;
use OC\Core\Service\LoginFlowV2Service;
use OCA\IntrusionDetection\Address\AddressResolver;
use OCA\IntrusionDetection\AppInfo\Application;
use OCA\IntrusionDetection\Check\Checks\LoginFlowMismatch;
use OCA\IntrusionDetection\Check\Checks\LoginFlowMismatchDetector;
use OCA\IntrusionDetection\Config\GlobalSettings;
use OCA\IntrusionDetection\Db\Detection;
use OCA\IntrusionDetection\Definition\Mode;
use OCA\IntrusionDetection\Definition\ResponseType;
use OCA\IntrusionDetection\Definition\Severity;
use OCA\IntrusionDetection\Explain\NarrativeBuilder;
use OCA\IntrusionDetection\Listener\LoginFlowGrantedListener;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Response\BanService;
use OCA\IntrusionDetection\Response\FlaggedSources;
use OCA\IntrusionDetection\Response\ResponseEngine;
use OCA\IntrusionDetection\TrustedNetwork\ITrustedNetworks;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\Authentication\Events\LoginFlowV2GrantedEvent;
use OCP\Authentication\Token\IToken;
use OCP\IUser;
use OCP\L10N\IFactory;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;

/**
 * Login request phishing (concept section 10.11), driven through core's
 * real login flow v2 service, which dispatches LoginFlowV2GrantedEvent when
 * a request is granted.
 */
#[Group('DB')]
class LoginFlowMismatchTest extends RequestEventTestCase {
	private const CLIENT = 'Nextcloud desktop (ids test)';

	private IUser $user;
	private ITrustedNetworks $trustedNetworks;

	protected function setUp(): void {
		parent::setUp();
		$this->user = $this->user('ids-flow');
		$this->trustedNetworks = Server::get(ITrustedNetworks::class);
		$this->listen(LoginFlowV2GrantedEvent::class, new LoginFlowGrantedListener(
			$this->settings,
			$this->addresses,
			$this->detector(),
			$this->request,
			Server::get(LoggerInterface::class),
		));
	}

	protected function tearDown(): void {
		$qb = $this->db->getQueryBuilder();
		$qb->delete('login_flow_v2')->where($qb->expr()->eq('client_name', $qb->createNamedParameter(self::CLIENT)))->executeStatement();
		parent::tearDown();
	}

	public function testHighWhenStartedFromABlockedAddress(): void {
		Server::get(BanService::class)->ban(SourceKey::fromIp('203.0.113.66'), 'manual');
		$detection = $this->grant('203.0.113.66', '198.51.100.7');
		$this->assertSame(Severity::High->value, $detection->getSeverity());
		$this->assertSame(LoginFlowMismatch::RULE_INITIATOR_BLOCKED, $detection->getExplanationData()['facts']['rule']);
		$this->assertSame('203.0.113.66', $detection->getIp(), 'The detection is about the address that started the request');
		$actions = $this->actions($detection);
		$this->assertSame([ResponseType::RevokeToken->value, ResponseType::NotifyAdmin->value, ResponseType::NotifyUser->value], array_keys($actions));
		$this->assertTrue($actions[ResponseType::RevokeToken->value]['enforced'], 'The app password created by the phished login is revoked');
		$this->assertTrue($actions[ResponseType::NotifyAdmin->value]['enforced']);
	}

	public function testHighWhenStartedFromAFlaggedAddressEvenInTheSameNetwork(): void {
		Server::get(FlaggedSources::class)->flagSource(SourceKey::fromIp('198.51.100.66'), FlaggedSources::REASON_ATTACK);
		$detection = $this->grant('198.51.100.66', '198.51.100.7');
		$this->assertSame(Severity::High->value, $detection->getSeverity());
		$this->assertSame(LoginFlowMismatch::RULE_INITIATOR_FLAGGED, $detection->getExplanationData()['facts']['rule']);
	}

	public function testMediumWhenStartedInAnotherNetwork(): void {
		$detection = $this->grant('203.0.113.5', '198.51.100.7');
		$this->assertSame(Severity::Medium->value, $detection->getSeverity());
		$facts = $detection->getExplanationData()['facts'];
		$this->assertSame(LoginFlowMismatch::RULE_OTHER_NETWORK, $facts['rule']);
		$this->assertSame('203.0.113.5', $facts['initiator']);
		$this->assertSame('198.51.100.7', $facts['granter']);
		$this->assertSame(self::CLIENT, $facts['client']);
		$this->assertSame($this->user->getUID(), $detection->getUid());
		$token = Server::get(IProvider::class)->getTokenById($facts['tokenId']);
		$this->assertSame($this->user->getUID(), $token->getUID(), 'The detection names the new app password by its id');
		$this->assertSame([ResponseType::NotifyAdmin->value, ResponseType::NotifyUser->value], array_keys($this->actions($detection)), 'Medium does not disconnect the device by default');
		$this->assertTrue(Server::get(LoginFlowMismatch::class)->asksWasThisYou($detection));

		$l = Server::get(IFactory::class)->get(Application::APP_ID, 'en');
		$notice = Server::get(LoginFlowMismatch::class)->userNotice($detection, $l);
		$this->assertSame('A new device was connected to your account', $notice->subject);
		$this->assertSame([
			'A new device was connected to your account.',
			'The request came from 203.0.113.5, you approved it from 198.51.100.7.',
			'If this was not you, remove the device in your security settings and change your password.',
		], $notice->message);
		$this->assertStringContainsString('The request was started from 203.0.113.5 and approved from 198.51.100.7, which is in another network.', implode(' ', Server::get(NarrativeBuilder::class)->build($detection, $l)->happened));
	}

	public function testMediumCanDisconnectTheDeviceWhenSwitchedOn(): void {
		$this->settings->setParam(LoginFlowMismatch::ID, 'medium_revoke', true);
		$detection = $this->grant('203.0.113.5', '198.51.100.7');
		$this->assertArrayHasKey(ResponseType::RevokeToken->value, $this->actions($detection));
	}

	public function testMediumWhenApprovedTooLate(): void {
		$detection = $this->grant('198.51.100.8', '198.51.100.7', 900);
		$this->assertSame(Severity::Medium->value, $detection->getSeverity());
		$facts = $detection->getExplanationData()['facts'];
		$this->assertSame(LoginFlowMismatch::RULE_TOO_OLD, $facts['rule']);
		$this->assertEqualsWithDelta(900, $facts['age'], 5);
		$l = Server::get(IFactory::class)->get(Application::APP_ID, 'en');
		$this->assertStringContainsString('The limit at that time was 10 minutes.', implode(' ', Server::get(NarrativeBuilder::class)->build($detection, $l)->happened));
	}

	public function testDualStackIsOnlyRecordedAsLow(): void {
		$detection = $this->grant('2001:db8::5', '198.51.100.7');
		$this->assertSame(Severity::Low->value, $detection->getSeverity());
		$this->assertSame(LoginFlowMismatch::RULE_OTHER_FAMILY, $detection->getExplanationData()['facts']['rule']);
		$this->assertSame([], $detection->getActionList(), 'Low is recorded only: nobody is told');
		$this->assertFalse(Server::get(LoginFlowMismatch::class)->asksWasThisYou($detection));
	}

	public function testTheRulesApplyInOrder(): void {
		// Different families and too old: the age rule comes first.
		$this->assertSame(LoginFlowMismatch::RULE_TOO_OLD, $this->grant('2001:db8::5', '198.51.100.7', 900)->getExplanationData()['facts']['rule']);
		// Another network and too old: the network rule comes first.
		$this->assertSame(LoginFlowMismatch::RULE_OTHER_NETWORK, $this->grant('203.0.113.5', '198.51.100.7', 900)->getExplanationData()['facts']['rule']);
	}

	public function testNothingWhenStartedAndApprovedInTheSameNetworkInTime(): void {
		$this->grant('198.51.100.8', '198.51.100.7', 0, false);
		$this->assertSame([], $this->detectionsOf(LoginFlowMismatch::ID));
	}

	public function testATrustedNetworkTurnsMediumIntoLow(): void {
		$this->trustedNetworks = $this->createMock(ITrustedNetworks::class);
		$this->trustedNetworks->method('isTrusted')->willReturnCallback(fn (string $uid, SourceKey $source): bool => $uid === $this->user->getUID() && $source->netKey === '203.0.113.0/24');
		$detection = $this->detectWithoutCore('203.0.113.5', '198.51.100.7');
		$this->assertSame(Severity::Low->value, $detection->getSeverity());
		$this->assertTrue($detection->getExplanationData()['facts']['trusted']);
		$this->assertSame([], $detection->getActionList());

		Server::get(BanService::class)->ban(SourceKey::fromIp('203.0.113.6'), 'manual');
		$this->assertSame(Severity::High->value, $this->detectWithoutCore('203.0.113.6', '198.51.100.7')->getSeverity(), 'High stays high');
	}

	public function testAFlowStartedBeforeAddressesWereRecordedIsOnlyJudgedByItsAge(): void {
		$this->detectWithoutCore(null, '198.51.100.7');
		$this->assertSame([], $this->detectionsOf(LoginFlowMismatch::ID));
		$detection = $this->detectWithoutCore(null, '198.51.100.7', 900);
		$this->assertSame(LoginFlowMismatch::RULE_TOO_OLD, $detection->getExplanationData()['facts']['rule']);
		$this->assertSame('198.51.100.7', $detection->getIp());
	}

	public function testOffSkipsAllWork(): void {
		$this->settings->setMode(LoginFlowMismatch::ID, Mode::Off);
		$this->grant('203.0.113.5', '198.51.100.7', 0, false);
		$this->assertSame([], $this->detectionsOf(LoginFlowMismatch::ID));
	}

	public function testObserveRecordsWhatItWouldHaveDone(): void {
		$this->settings->setGlobal(GlobalSettings::LEARNING_UNTIL, time() + 86400);
		$detection = $this->grant('203.0.113.5', '198.51.100.7');
		$this->assertFalse($detection->isEnforced());
		foreach ($detection->getActionList() as $action) {
			$this->assertFalse($action['enforced']);
		}
	}

	/**
	 * Start a login flow from one address and grant it from another, through core.
	 */
	private function grant(string $initiator, string $granter, int $age = 0, bool $expectDetection = true): ?Detection {
		$service = Server::get(LoginFlowV2Service::class);
		$tokens = $service->createTokens(self::CLIENT, $initiator);
		if ($age > 0) {
			$flow = Server::get(LoginFlowV2Mapper::class)->getByLoginToken($tokens->getLoginToken());
			$flow->setTimestamp(time() - $age);
			Server::get(LoginFlowV2Mapper::class)->update($flow);
		}
		$sessionId = 'ids-session-' . bin2hex(random_bytes(16));
		Server::get(IProvider::class)->generateToken($sessionId, $this->user->getUID(), $this->user->getUID(), null, 'browser', IToken::TEMPORARY_TOKEN);

		$this->remoteAddress = $granter;
		$before = count($this->detectionsOf(LoginFlowMismatch::ID));
		$this->assertTrue($service->flowDone($tokens->getLoginToken(), $sessionId, 'https://cloud.example.com', $this->user->getUID()));
		$detections = $this->detectionsOf(LoginFlowMismatch::ID);
		if (!$expectDetection) {
			$this->assertCount($before, $detections);
			return null;
		}
		$this->assertCount($before + 1, $detections);
		return $detections[0];
	}

	/**
	 * Run the detector with an app password of the test user, for flows core
	 * can no longer create (without a starting address) or with a test
	 * double for the trusted networks.
	 */
	private function detectWithoutCore(?string $initiator, string $granter, int $age = 0): ?Detection {
		$token = $this->createMock(IToken::class);
		$token->method('getUID')->willReturn($this->user->getUID());
		$token->method('getName')->willReturn(self::CLIENT);
		$token->method('getId')->willReturn(4242);
		$this->detector()->granted($token, $initiator, time() - $age, SourceKey::fromIp($granter), null);
		return $this->detectionsOf(LoginFlowMismatch::ID)[0] ?? null;
	}

	private function detector(): LoginFlowMismatchDetector {
		return new LoginFlowMismatchDetector(
			$this->settings,
			Server::get(ResponseEngine::class),
			Server::get(LoginFlowMismatch::class),
			Server::get(AddressResolver::class),
			Server::get(FlaggedSources::class),
			$this->addresses,
			$this->trustedNetworks,
			Server::get(ITimeFactory::class),
		);
	}

	/**
	 * @return array<string, array{type: string, enforced: bool, ref?: mixed, note?: string}>
	 */
	private function actions(Detection $detection): array {
		$actions = [];
		foreach ($detection->getActionList() as $action) {
			$actions[$action['type']] = $action;
		}
		return $actions;
	}
}
