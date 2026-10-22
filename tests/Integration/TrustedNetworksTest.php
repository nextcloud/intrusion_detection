<?php

declare(strict_types=1);

/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\IntrusionDetection\Tests\Integration;

use OCA\IntrusionDetection\Audit\AuditLogger;
use OCA\IntrusionDetection\BackgroundJob\Cleanup;
use OCA\IntrusionDetection\Config\Settings;
use OCA\IntrusionDetection\Confirm\UnconfirmedSessions;
use OCA\IntrusionDetection\Crypto\Fingerprinter;
use OCA\IntrusionDetection\Db\StepUpSessionMapper;
use OCA\IntrusionDetection\Db\TrustedNetworkMapper;
use OCA\IntrusionDetection\Net\SourceKey;
use OCA\IntrusionDetection\Privacy\UserDataCleanup;
use OCA\IntrusionDetection\State\HotState;
use OCA\IntrusionDetection\TrustedNetwork\ITrustedNetworks;
use OCA\IntrusionDetection\TrustedNetwork\TrustedNetworks;
use OCP\AppFramework\Utility\ITimeFactory;
use OCP\IConfig;
use OCP\Server;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;

/**
 * Trusted networks (concept section 7) and the server-side record of
 * unconfirmed sessions: storage, expiry, ownership and cleanup.
 */
#[Group('DB')]
class TrustedNetworksTest extends IntegrationTestCase {
	private int $now = 1_800_000_000;

	public function testANetworkIsTrustedForTheUserForTheConfiguredTime(): void {
		$networks = $this->networks();
		$this->assertInstanceOf(TrustedNetworks::class, Server::get(ITrustedNetworks::class), 'The real implementation is registered');
		$until = $networks->trust('alice', SourceKey::fromIp('203.0.113.7'), 42);
		$this->assertSame($this->now + 30 * 86400, $until);
		$this->assertTrue($networks->isTrusted('alice', SourceKey::fromIp('203.0.113.250')), 'The whole /24');
		$this->assertFalse($networks->isTrusted('alice', SourceKey::fromIp('203.0.114.7')));
		$this->assertFalse($networks->isTrusted('bob', SourceKey::fromIp('203.0.113.7')), 'Only for that user');
		$this->assertFalse($networks->isTrusted('alice', SourceKey::fromIp('2001:db8:1:2::99')), 'Not trusted yet');

		$networks->trust('alice', SourceKey::fromIp('2001:db8:1:2::1'));
		$this->assertTrue($networks->isTrusted('alice', SourceKey::fromIp('2001:db8:1:2:ffff::1')), 'IPv6: the /64');
		$this->assertCount(2, $networks->forUser('alice'));

		$this->now += 30 * 86400;
		$this->assertFalse($networks->isTrusted('alice', SourceKey::fromIp('203.0.113.7')), 'Expired');
		$this->assertSame([], $networks->forUser('alice'));
	}

	public function testTrustingAgainRenewsTheOneEntry(): void {
		$networks = $this->networks();
		$networks->trust('alice', SourceKey::fromIp('203.0.113.7'));
		$this->now += 86400;
		$until = $networks->trust('alice', SourceKey::fromIp('203.0.113.8'), 7);
		$list = $networks->forUser('alice');
		$this->assertCount(1, $list);
		$this->assertSame($until, $list[0]['expiresAt']);
		$this->assertSame(7, $list[0]['detectionId']);
	}

	public function testUsersRemoveOnlyTheirOwnEntries(): void {
		$networks = $this->networks();
		$networks->trust('alice', SourceKey::fromIp('203.0.113.7'));
		$networks->trust('bob', SourceKey::fromIp('198.51.100.7'));
		$bobs = $networks->forUser('bob')[0]['id'];
		$this->assertFalse($networks->remove('alice', $bobs));
		$this->assertCount(1, $networks->forUser('bob'));
		$this->assertTrue($networks->remove('bob', $bobs));
		$this->assertSame([], $networks->forUser('bob'));
		$networks->distrust('alice', SourceKey::fromIp('203.0.113.99'));
		$this->assertSame([], $networks->forUser('alice'));
	}

	public function testExpiredRowsAreCleanedUpAndDeletedAccountsLeaveNothing(): void {
		$networks = Server::get(TrustedNetworks::class);
		$networks->trust('ids-gone-user', SourceKey::fromIp('203.0.113.7'));
		Server::get(TrustedNetworkMapper::class)->trust('ids-old-user', '192.0.2.0/24', null, time() - 100, time() - 1);
		Server::get(StepUpSessionMapper::class)->record('a', 'ids-gone-user', time(), time() + 3600);
		Server::get(StepUpSessionMapper::class)->record('b', 'ids-old-user', time() - 100, time() - 1);

		self::invokePrivate(Server::get(Cleanup::class), 'run', [null]);
		$this->assertSame([], Server::get(TrustedNetworks::class)->forUser('ids-old-user'));
		$this->assertNull(Server::get(StepUpSessionMapper::class)->find('b', time() - 10), 'Deleted, not just expired');

		Server::get(UserDataCleanup::class)->deleteUser('ids-gone-user');
		$this->assertSame([], $networks->forUser('ids-gone-user'));
		$this->assertNull(Server::get(StepUpSessionMapper::class)->find('a', time()));
	}

	public function testUnconfirmedSessionsAreKeptByFingerprintAndOnlyReadWhileOneMayExist(): void {
		$sessions = Server::get(UnconfirmedSessions::class);
		$this->assertFalse($sessions->mayExist());
		$this->assertNull($sessions->accountOf('some-session-id'));

		$sessions->remember('the-session-id-is-a-token-secret', 'alice');
		$this->assertTrue($sessions->mayExist());
		$this->assertSame('alice', $sessions->accountOf('the-session-id-is-a-token-secret'));
		$this->assertNull($sessions->accountOf('another-session'));

		$qb = $this->db->getQueryBuilder();
		$rows = $qb->select('*')->from(StepUpSessionMapper::TABLE)->executeQuery()->fetchAll();
		$this->assertCount(1, $rows);
		$this->assertSame(Server::get(Fingerprinter::class)->session('the-session-id-is-a-token-secret'), $rows[0]['session_key']);
		$this->assertStringNotContainsString('the-session-id', json_encode($rows, JSON_THROW_ON_ERROR), 'Never the session id itself');
		$lifetime = (int)$rows[0]['expires_at'] - (int)$rows[0]['created_at'];
		$config = Server::get(IConfig::class);
		$this->assertSame(max($config->getSystemValueInt('remember_login_cookie_lifetime', 15 * 86400), $config->getSystemValueInt('session_lifetime', 86400)) + 3600, $lifetime, 'As long as core could resume the session');

		$sessions->forget('the-session-id-is-a-token-secret');
		$this->assertNull($sessions->accountOf('the-session-id-is-a-token-secret'));

		$mapper = $this->createMock(StepUpSessionMapper::class);
		$mapper->expects($this->never())->method('find');
		Server::get(HotState::class)->setStepUpSessionsUntil(0);
		$quiet = new UnconfirmedSessions($mapper, Server::get(Fingerprinter::class), $config, Server::get(ITimeFactory::class), Server::get(LoggerInterface::class), Server::get(HotState::class));
		$this->assertNull($quiet->accountOf('any'), 'Normal logins cost no query');
	}

	private function networks(): TrustedNetworks {
		$time = $this->createMock(ITimeFactory::class);
		$time->method('getTime')->willReturnCallback(fn (): int => $this->now);
		return new TrustedNetworks(Server::get(TrustedNetworkMapper::class), $time, Server::get(AuditLogger::class));
	}

	private function settings(): Settings {
		return Server::get(Settings::class);
	}
}
